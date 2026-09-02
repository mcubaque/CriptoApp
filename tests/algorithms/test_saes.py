from app.algorithms.symmetric_modern import saes

# Verified step-by-step (including every GF(2^4) multiplication) against
# Steven Gordon's "Simplified AES Example" (SIIT CSS 322, 3 Dec 2009).
KEY = "0100101011110101"
PLAINTEXT = "1101011100101000"
CIPHERTEXT = "0010010011101100"
KEY0 = "0100101011110101"
KEY1 = "1101110100101000"
KEY2 = "1000011110101111"


def test_gf_mult_matches_reference_products():
    assert saes._gf_mult(4, 0b1110) == 0b1101  # 4 x E = D
    assert saes._gf_mult(4, 0b0010) == 0b1000  # 4 x 2 = 8
    assert saes._gf_mult(9, 0b1111) == 0b1110  # 9 x F = E
    assert saes._gf_mult(2, 0b1111) == 0b1101  # 2 x F = D
    assert saes._gf_mult(9, 0b0110) == 0b0011  # 9 x 6 = 3
    assert saes._gf_mult(2, 0b0110) == 0b1100  # 2 x 6 = C
    assert saes._gf_mult(9, 0b0011) == 0b1000  # 9 x 3 = 8
    assert saes._gf_mult(2, 0b0011) == 0b0110  # 2 x 3 = 6


def test_key_schedule_matches_reference():
    key0, key1, key2, _ = saes.generate_keys(KEY)
    assert key0 == KEY0
    assert key1 == KEY1
    assert key2 == KEY2


def test_encrypt_matches_reference_example():
    result = saes.encrypt(PLAINTEXT, KEY)
    assert result.ok is True
    assert result.output == CIPHERTEXT


def test_decrypt_matches_reference_example():
    result = saes.decrypt(CIPHERTEXT, KEY)
    assert result.ok is True
    assert result.output == PLAINTEXT


def test_roundtrip_arbitrary_block():
    enc = saes.encrypt("1010101010101010", "1111000011110000")
    dec = saes.decrypt(enc.output, "1111000011110000")
    assert dec.output == "1010101010101010"


def test_invalid_key_length_rejected():
    result = saes.encrypt(PLAINTEXT, "101")
    assert result.ok is False
