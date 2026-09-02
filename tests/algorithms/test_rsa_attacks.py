from app.algorithms.asymmetric import rsa, rsa_attacks


def test_factor_bruteforce_recovers_classic_pq():
    result = rsa_attacks.factor_bruteforce(3233)  # 61 * 53, from test_rsa.py
    assert result.output == "p=53, q=61"


def test_factor_bruteforce_rejects_prime_n():
    result = rsa_attacks.factor_bruteforce(3299)  # prime
    assert result.ok is False


def test_common_modulus_attack_recovers_message():
    n = 3233
    m = 65
    e1, e2 = 17, 19  # gcd(17,19) = 1
    c1 = int(rsa.encrypt(m, e1, n).output)
    c2 = int(rsa.encrypt(m, e2, n).output)
    result = rsa_attacks.common_modulus_attack(n, e1, c1, e2, c2)
    assert result.ok is True
    assert result.output == str(m)


def test_wiener_attack_recovers_small_d():
    # Verified empirically: p=53, q=59, n=3127, phi=3016, d=7, e=431 (7*431 mod 3016 == 1).
    result = rsa_attacks.wiener_attack(431, 3127)
    assert result.ok is True
    assert result.output == "d=7 (p=59, q=53)"


def test_wiener_attack_fails_for_large_d():
    # e chosen so that d is NOT small -- Wiener's condition shouldn't hold.
    result = rsa_attacks.wiener_attack(17, 3233)  # classic pair, d=2753 (large)
    assert result.ok is False
