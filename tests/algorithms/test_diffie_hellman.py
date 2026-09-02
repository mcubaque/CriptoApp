from app.algorithms.asymmetric import diffie_hellman

# Classic textbook DH example (Wikipedia "Diffie-Hellman key exchange"):
# p=23, g=5, a=6, b=15 -> A=8, B=19, shared secret=2.


def test_exchange_matches_classic_example():
    result = diffie_hellman.exchange(p=23, g=5, a=6, b=15)
    assert result.ok is True
    assert result.output == "2"


def test_non_prime_modulus_rejected():
    result = diffie_hellman.exchange(p=24, g=5, a=6, b=15)
    assert result.ok is False


def test_secrets_always_match_for_valid_inputs():
    result = diffie_hellman.exchange(p=97, g=5, a=36, b=58)
    assert result.ok is True
    assert result.steps[-1].ok is True
