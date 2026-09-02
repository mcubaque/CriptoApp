from app.algorithms.asymmetric import rsa

# Classic textbook RSA example (Wikipedia "RSA (cryptosystem)"): p=61, q=53,
# e=17 -> n=3233, phi=3120, d=2753; m=65 -> c=2790.


def test_keygen_matches_classic_example():
    result = rsa.keygen(p=61, q=53, e=17)
    assert result.ok is True
    assert result.output == "n=3233, e=17, d=2753"


def test_encrypt_matches_classic_example():
    result = rsa.encrypt(m=65, e=17, n=3233)
    assert result.output == "2790"


def test_decrypt_matches_classic_example():
    result = rsa.decrypt(c=2790, d=2753, n=3233)
    assert result.output == "65"


def test_non_prime_rejected():
    result = rsa.keygen(p=60, q=53, e=17)
    assert result.ok is False


def test_invalid_e_rejected():
    result = rsa.keygen(p=61, q=53, e=6)  # gcd(6,3120) != 1
    assert result.ok is False


def test_encrypt_decrypt_roundtrip_small():
    key = rsa.keygen(p=11, q=13, e=7)  # n=143, phi=120
    assert key.ok is True
    n = 11 * 13
    d = int(key.output.split("d=")[1])
    enc = rsa.encrypt(m=42, e=7, n=n)
    dec = rsa.decrypt(c=int(enc.output), d=d, n=n)
    assert dec.output == "42"
