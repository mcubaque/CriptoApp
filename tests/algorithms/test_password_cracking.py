from app.algorithms.authentication import password_cracking
from app.algorithms.authentication.hash_demo import _digest


def test_dictionary_attack_finds_known_password():
    target = _digest("admin", "sha256")
    result = password_cracking.crack_dictionary(target)
    assert result.output == "admin"


def test_dictionary_attack_misses_unknown_password():
    target = _digest("zz_not_in_the_list_zz", "sha256")
    result = password_cracking.crack_dictionary(target)
    assert result.output is None


def test_bruteforce_finds_short_password():
    target = _digest("ab", "sha256")
    result = password_cracking.crack_bruteforce(target, charset="abc", max_length=2)
    assert result.output == "ab"


def test_bruteforce_rejects_oversized_search_space():
    target = _digest("x", "sha256")
    result = password_cracking.crack_bruteforce(
        target, charset="abcdefghijklmnopqrstuvwxyz0123456789", max_length=5
    )
    assert result.ok is False


def test_salt_demo_produces_different_hashes():
    result = password_cracking.salt_demo("mypassword", "salt1", "salt2")
    assert result.steps[-1].ok is True
