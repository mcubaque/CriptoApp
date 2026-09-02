from app.algorithms.asymmetric import hybrid

# p=251, q=263 (both prime, verified) -> n=66013 > 65535, so any 16-bit session
# key fits in one RSA block. e=17, d=3853 (verified: e*d mod phi(n) == 1).
N = 66013
E = 17
D = 3853
SESSION_KEY = "1010110011000101"[:16]  # arbitrary 16-bit key


def test_encrypt_then_decrypt_roundtrip():
    enc = hybrid.encrypt("Hi!", SESSION_KEY, E, N)
    assert enc.ok is True

    encrypted_key = int(enc.output.split("llave_cifrada=")[1].split(" |")[0])
    cipher_blocks = enc.output.split("bloques=")[1]

    dec = hybrid.decrypt(encrypted_key, cipher_blocks, D, N)
    assert dec.ok is True
    assert dec.output == "Hi!"


def test_encrypt_rejects_invalid_session_key():
    result = hybrid.encrypt("hola", "101", E, N)
    assert result.ok is False


def test_encrypt_propagates_rsa_error_when_key_too_big_for_n():
    small_n = 3233  # from the classic RSA example; too small for a 16-bit key
    result = hybrid.encrypt("hola", SESSION_KEY, 17, small_n)
    assert result.ok is False
