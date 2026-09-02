from app.algorithms.classical import shift


def test_encrypt_matches_reading_example():
    result = shift.encrypt("wewillmeetatmidnight", 11)
    assert result.output == "HPHTWWXPPELEXTOYTRSE"


def test_decrypt_is_inverse_of_encrypt():
    enc = shift.encrypt("attackatdawn", 7)
    dec = shift.decrypt(enc.output, 7)
    assert dec.output == "ATTACKATDAWN"


def test_crack_bruteforce_recovers_plaintext():
    result = shift.crack_bruteforce("JBCRCLQRWCRVNBJENBWRWN")
    assert result.output == "ASTITCHINTIMESAVESNINE"


def test_crack_frequency_hypothesis_recovers_key():
    ciphertext = shift.encrypt("thequickbrownfoxjumps", 5).output
    result = shift.crack_frequency_hypothesis(ciphertext, cipher_letter="Y", plain_letter="T")
    assert result.steps[1].formula.endswith("= 5")
