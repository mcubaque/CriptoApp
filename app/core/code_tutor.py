"""'Python Tutor'-style execution tracer: runs one of our own algorithm
functions under sys.settrace and records, line by line, exactly what the
interpreter did -- current line, local variables, call depth -- across the
whole call graph of OUR OWN code (not standard-library internals).

The filter is by FILE, not by an explicit function allowlist: any frame whose
source file lives under app/algorithms/, or is app/core/numeric_utils.py or
app/core/text_utils.py, gets traced. That means tracing e.g. rsa.encrypt
automatically follows the execution into numeric_utils.mod_pow_steps, and
tracing hybrid.encrypt automatically follows into both rsa.encrypt and
saes.encrypt, with no per-algorithm wiring needed. app/core/step_trace.py and
history_service.py are deliberately NOT included: they're app plumbing (the
Step/AlgorithmRunResult bookkeeping), not the algorithm logic itself.

This is a genuinely different view from the Step/StepTable narrative trace:
that one explains WHAT happens in prose; this one shows literally HOW the
Python code gets there, one line at a time.
"""
from __future__ import annotations

import inspect
import os
import sys
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Callable

MAX_TRACE_STEPS = 3000
MAX_LIST_ITEMS = 30
MAX_STRING_LEN = 300
MAX_SERIALIZE_DEPTH = 4

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../app
_ALGORITHMS_DIR = os.path.normcase(os.path.join(_APP_DIR, "algorithms") + os.sep)
_INCLUDED_CORE_FILES = {
    os.path.normcase(os.path.join(_APP_DIR, "core", "numeric_utils.py")),
    os.path.normcase(os.path.join(_APP_DIR, "core", "text_utils.py")),
}


def _is_traced_file(filename: str) -> bool:
    norm = os.path.normcase(os.path.abspath(filename))
    return norm in _INCLUDED_CORE_FILES or norm.startswith(_ALGORITHMS_DIR)


def _serialize_value(value: Any, depth: int = 0) -> Any:
    if depth > MAX_SERIALIZE_DEPTH:
        return "…"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING_LEN else value[:MAX_STRING_LEN] + "…"
    if isinstance(value, (list, tuple)):
        items = [_serialize_value(v, depth + 1) for v in list(value)[:MAX_LIST_ITEMS]]
        if len(value) > MAX_LIST_ITEMS:
            items.append(f"… (+{len(value) - MAX_LIST_ITEMS} más)")
        return items
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= MAX_LIST_ITEMS:
                out["…"] = f"(+{len(value) - MAX_LIST_ITEMS} más)"
                break
            out[str(k)] = _serialize_value(v, depth + 1)
        return out
    if is_dataclass(value) and not isinstance(value, type):
        return _serialize_value(asdict(value), depth + 1)
    text = repr(value)
    return text if len(text) <= MAX_STRING_LEN else text[:MAX_STRING_LEN] + "…"


@dataclass
class TraceStep:
    event: str  # "line" | "return"
    function: str
    file_key: str
    line_no: int
    depth: int
    locals: dict
    return_value: Any = None


@dataclass
class FunctionSource:
    file_key: str
    function: str
    start_line: int
    lines: list


@dataclass
class TutorTrace:
    ok: bool
    result: Any
    steps: list = field(default_factory=list)
    sources: dict = field(default_factory=dict)
    truncated: bool = False
    error: str | None = None

    def to_payload(self) -> dict:
        return {
            "ok": self.ok,
            "error": self.error,
            "truncated": self.truncated,
            "steps": [asdict(s) for s in self.steps],
            "sources": {k: asdict(v) for k, v in self.sources.items()},
        }


def _file_key(filename: str, func_name: str) -> str:
    base = os.path.basename(filename).replace(".py", "")
    return f"{base}.{func_name}"


def trace_call(func: Callable, args: tuple = (), kwargs: dict | None = None) -> TutorTrace:
    kwargs = kwargs or {}
    steps: list[TraceStep] = []
    sources: dict[str, FunctionSource] = {}
    call_stack: list[int] = []
    state = {"truncated": False}

    def capture_source(frame) -> str:
        filename = frame.f_code.co_filename
        func_name = frame.f_code.co_name
        key = _file_key(filename, func_name)
        if key not in sources:
            try:
                lines, start = inspect.getsourcelines(frame)
                sources[key] = FunctionSource(
                    file_key=key, function=func_name, start_line=start,
                    lines=[l.rstrip("\n") for l in lines],
                )
            except (OSError, TypeError):
                sources[key] = FunctionSource(
                    file_key=key, function=func_name, start_line=frame.f_lineno,
                    lines=["<código fuente no disponible>"],
                )
        return key

    def make_local_tracer(frame_depth: int):
        def local_tracer(frame, event, arg):
            if state["truncated"]:
                return None
            if event in ("line", "return"):
                if len(steps) >= MAX_TRACE_STEPS:
                    state["truncated"] = True
                    return None
                key = capture_source(frame)
                snapshot = {
                    k: _serialize_value(v) for k, v in frame.f_locals.items() if not k.startswith("__")
                }
                steps.append(
                    TraceStep(
                        event=event,
                        function=frame.f_code.co_name,
                        file_key=key,
                        line_no=frame.f_lineno,
                        depth=frame_depth,
                        locals=snapshot,
                        return_value=_serialize_value(arg) if event == "return" else None,
                    )
                )
                if event == "return" and call_stack and call_stack[-1] == id(frame):
                    call_stack.pop()
            return local_tracer

        return local_tracer

    def global_tracer(frame, event, arg):
        if event != "call" or state["truncated"]:
            return None
        if not _is_traced_file(frame.f_code.co_filename):
            return None
        if len(steps) >= MAX_TRACE_STEPS:
            state["truncated"] = True
            return None
        depth = len(call_stack)
        call_stack.append(id(frame))
        return make_local_tracer(depth)

    old_trace = sys.gettrace()
    sys.settrace(global_tracer)
    error = None
    result = None
    ok = True
    try:
        result = func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: this is a debugging tool
        ok = False
        error = f"{type(exc).__name__}: {exc}"
    finally:
        sys.settrace(old_trace)

    return TutorTrace(
        ok=ok, result=result, steps=steps, sources=sources,
        truncated=state["truncated"], error=error,
    )
