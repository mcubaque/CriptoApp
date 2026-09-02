from app.algorithms.classical import transposition


def test_encrypt_decrypt_roundtrip():
    key = [3, 1, 4, 2, 6, 5]
    plaintext = "SHESELLSSEASHELLSBYTHESEASHOREX"
    enc = transposition.encrypt(plaintext, key)
    assert enc.ok is True
    dec = transposition.decrypt(enc.output, key)
    assert dec.output.rstrip("X") == plaintext.rstrip("X") or dec.output == plaintext


def test_invalid_permutation_rejected():
    result = transposition.encrypt("HELLO", [1, 2, 2])
    assert result.ok is False
