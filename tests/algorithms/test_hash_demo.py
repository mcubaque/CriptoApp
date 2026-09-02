from app.algorithms.authentication import hash_demo

# sha256("") is a universally known public constant, good external verification.
SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_matches_known_vector():
    result = hash_demo.compute_hash("", "sha256")
    assert result.output == SHA256_EMPTY


def test_unsupported_algorithm_rejected():
    result = hash_demo.compute_hash("hola", "sha999")
    assert result.ok is False


def test_avalanche_effect_is_large_for_single_char_change():
    result = hash_demo.avalanche_demo("hello", "hellp")
    diff_bits = result.steps[-1].extra["diff_bits"]
    total_bits = result.steps[-1].extra["total_bits"]
    assert diff_bits / total_bits > 0.25


def test_hmac_is_deterministic_and_key_dependent():
    a = hash_demo.hmac_demo("secret", "message")
    b = hash_demo.hmac_demo("secret", "message")
    c = hash_demo.hmac_demo("other-secret", "message")
    assert a.output == b.output
    assert a.output != c.output
