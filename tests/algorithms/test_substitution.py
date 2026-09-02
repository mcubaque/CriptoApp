from app.algorithms.classical import substitution

KEY = "XNYAHPOGZQWBTSFLRCVMUEKJDI"  # a..z -> this string, per the reading's table


def test_decrypt_matches_reading_example():
    result = substitution.decrypt("MGZVYZLGHCMHJMYXSSFMNHAHYCDLMHA", KEY)
    assert result.output == "THISCIPHERTEXTCANNOTBEDECRYPTED"


def test_encrypt_decrypt_roundtrip():
    enc = substitution.encrypt("HELLOWORLD", KEY)
    dec = substitution.decrypt(enc.output, KEY)
    assert dec.output == "HELLOWORLD"


def test_invalid_key_rejected():
    result = substitution.encrypt("HELLO", "ABC")
    assert result.ok is False


def test_crack_interactive_partial_mapping_reveals_known_letters():
    result = substitution.crack_interactive("MGZVYZLGHC", {"M": "T", "G": "H"})
    assert result.output.startswith("TH")
