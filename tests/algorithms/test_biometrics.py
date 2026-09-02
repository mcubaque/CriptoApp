from app.algorithms.authentication import biometrics


def test_identical_templates_are_100_percent_similar_and_accepted():
    result = biometrics.match("10110010", "10110010", threshold_pct=100)
    assert result.output == "ACEPTAR"


def test_threshold_zero_always_accepts():
    result = biometrics.match("11111111", "00000000", threshold_pct=0)
    assert result.output == "ACEPTAR"


def test_threshold_over_100_always_rejects_unless_identical():
    result = biometrics.match("11110000", "11110001", threshold_pct=100)
    assert result.output == "RECHAZAR"


def test_mismatched_lengths_rejected():
    result = biometrics.match("101", "1010", threshold_pct=50)
    assert result.ok is False


def test_hamming_distance_is_correct():
    result = biometrics.match("1111", "1010", threshold_pct=50)
    # differ at positions 2 and 4 -> distance 2 of 4 -> similarity 50%
    assert result.steps[1].formula.endswith("50.0%")


def test_far_frr_sweep_produces_a_row_per_threshold():
    result = biometrics.far_frr_sweep([90, 50])
    table = result.steps[1].table
    assert len(table.rows) == 2
