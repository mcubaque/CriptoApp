from app.algorithms.symmetric_modern import sdes

# Verified bit-by-bit against a fully worked S-DES reference example
# (ISE334/SE425 Recitation 3, Stallings-based): K=1100011110, P=00101000
# -> K1=11101001, K2=10100111, IP(P)=00100010, C=10001010.
KEY = "1100011110"
PLAINTEXT = "00101000"
CIPHERTEXT = "10001010"


def test_key_schedule_matches_reference():
    k1, k2, _ = sdes.generate_keys(KEY)
    assert k1 == "11101001"
    assert k2 == "10100111"


def test_encrypt_matches_reference_example():
    result = sdes.encrypt(PLAINTEXT, KEY)
    assert result.ok is True
    assert result.output == CIPHERTEXT


def test_decrypt_is_inverse_of_encrypt():
    result = sdes.decrypt(CIPHERTEXT, KEY)
    assert result.output == PLAINTEXT


def test_roundtrip_arbitrary_block():
    enc = sdes.encrypt("11010111", "0111111101")
    dec = sdes.decrypt(enc.output, "0111111101")
    assert dec.output == "11010111"


def test_invalid_key_length_rejected():
    result = sdes.encrypt(PLAINTEXT, "101")
    assert result.ok is False
