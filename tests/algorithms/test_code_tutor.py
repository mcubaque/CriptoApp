from app.algorithms.asymmetric import rsa
from app.algorithms.classical import shift
from app.algorithms.symmetric_modern import saes
from app.core.code_tutor import MAX_TRACE_STEPS, trace_call


def test_trace_matches_direct_call_result():
    direct = shift.encrypt("wewillmeetatmidnight", 11)
    traced = trace_call(shift.encrypt, args=("wewillmeetatmidnight", 11))
    assert traced.ok is True
    assert traced.result.output == direct.output == "HPHTWWXPPELEXTOYTRSE"


def test_trace_captures_line_and_return_events():
    traced = trace_call(shift.encrypt, args=("abc", 3))
    assert len(traced.steps) > 5
    assert any(s.event == "return" for s in traced.steps)
    assert all(s.event in ("line", "return") for s in traced.steps)


def test_trace_captures_locals_changing_across_iterations():
    traced = trace_call(shift.encrypt, args=("abcd", 1))
    # 'ch' is the loop variable inside encrypt(); it should take on several
    # distinct values across the trace as the loop iterates.
    ch_values = {s.locals.get("ch") for s in traced.steps if "ch" in s.locals}
    assert len(ch_values) >= 2


def test_trace_follows_into_helper_files_under_algorithms_or_core():
    # rsa.encrypt() calls numeric_utils.mod_pow_steps() -- the trace should
    # include frames from BOTH files, not just rsa.py.
    traced = trace_call(rsa.encrypt, args=(65, 17, 3233))
    functions_seen = {s.function for s in traced.steps}
    assert "encrypt" in functions_seen
    assert "mod_pow_steps" in functions_seen


def test_trace_of_composite_function_follows_into_other_algorithm_modules():
    # saes.encrypt calls its own private helpers (_sub_nibbles, _mix_columns...)
    # all defined in the same file -- confirms multi-level nested calls trace fine.
    traced = trace_call(saes.encrypt, args=("1101011100101000", "0100101011110101"))
    assert traced.ok is True
    assert traced.result.output == "0010010011101100"
    depths = {s.depth for s in traced.steps}
    assert len(depths) >= 2  # at least top-level (0) and one nested helper call


def test_trace_source_is_captured_for_each_function_seen():
    traced = trace_call(shift.encrypt, args=("ab", 1))
    functions_seen = {s.function for s in traced.steps}
    keys_seen = {s.file_key for s in traced.steps}
    assert keys_seen <= set(traced.sources.keys())
    for key in keys_seen:
        assert len(traced.sources[key].lines) > 0


def test_trace_handles_exceptions_gracefully():
    def broken(x):
        return 1 / x

    traced = trace_call(broken, args=(0,))
    assert traced.ok is False
    assert "ZeroDivisionError" in traced.error


def test_trace_truncates_very_long_loops(monkeypatch):
    # long_loop() lives in the test file, outside app/algorithms/, so it
    # wouldn't normally qualify for tracing -- force-include it here just to
    # exercise the truncation safeguard in isolation.
    import app.core.code_tutor as code_tutor

    monkeypatch.setattr(code_tutor, "_is_traced_file", lambda filename: True)

    def long_loop():
        total = 0
        for i in range(MAX_TRACE_STEPS * 3):
            total += i
        return total

    traced = code_tutor.trace_call(long_loop, args=())
    assert traced.truncated is True
    assert len(traced.steps) <= MAX_TRACE_STEPS
