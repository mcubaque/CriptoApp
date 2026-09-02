from app.algorithms.classical import affine


def test_encrypt_matches_reading_example():
    # The reading's printed ciphertext ("CFFCQUYCYJEEPCBRECX0XPE") has OCR
    # artifacts (Y/Z confusion, 0/O confusion, a dropped W). Verified by hand
    # against the reading's own explicit integer sequence for this example:
    # plaintext ints 0 19 19 0 2 10 7 0 18 1 4 4 13 0 11 17 4 0 3 24 3 14 13 4
    # -> cipher ints 2 5 5 2 16 20 25 2 24 9 4 4 15 2 1 17 4 2 23 14 23 22 15 4
    # which decodes to CFFCQUZCYJEEPCBRECXOXWPE.
    result = affine.encrypt("attackhasbeenalreadydone", a=7, b=2)
    assert result.output == "CFFCQUZCYJEEPCBRECXOXWPE"


def test_illegal_key_is_rejected():
    result = affine.encrypt("hello", a=2, b=3)
    assert result.ok is False
    assert "ilegal" in result.error.lower() or "gcd" in result.error.lower()


def test_decrypt_is_inverse_of_encrypt():
    enc = affine.encrypt("ATTACKATDAWN", a=5, b=8)
    dec = affine.decrypt(enc.output, a=5, b=8)
    assert dec.output == "ATTACKATDAWN"


def test_crack_frequency_hypothesis_finds_legal_key():
    ciphertext = "FMXVEDKAPHFERBNDKRXRSREFMORUDSDKDVSHVUFEDKAPRKDLYEVLRHHRH"
    result = affine.crack_frequency_hypothesis(
        ciphertext, cipher_letter_1="R", plain_letter_1="e",
        cipher_letter_2="K", plain_letter_2="t",
    )
    assert result.ok is True
    # The reading's transcription ("...ofarimethicprocesses") has an OCR typo;
    # decrypting with the derived key (a=3, b=5) mathematically yields the
    # correctly spelled English word "arithmetic".
    assert result.output == "algorithmsarequitegeneraldefinitionsofarithmeticprocesses".upper()
