from app.algorithms.pki import certificates

# Three independently-verified RSA keypairs (see test_rsa.py / test_hybrid.py
# for the classic and hybrid ones; the third is verified inline below).
ROOT = {"e": 17, "d": 3853, "n": 66013}
INTERMEDIATE = {"e": 17, "d": 2753, "n": 3233}
END_ENTITY = {"e": 17, "d": 3953, "n": 11413}


def test_end_entity_keypair_is_valid():
    # p=101, q=113 -> n=11413, phi=11200, e=17, d=3953
    assert (END_ENTITY["e"] * END_ENTITY["d"]) % 11200 == 1


def test_self_signed_certificate_verifies():
    cert = certificates.issue_certificate("Root CA", ROOT["e"], ROOT["n"], "Root CA", ROOT["d"], ROOT["n"])
    sig = cert.steps[-1].extra["signature"]
    result = certificates.verify_certificate(
        "Root CA", "Root CA", ROOT["e"], ROOT["n"], "2026-01-01", "2027-01-01", sig, ROOT["e"], ROOT["n"]
    )
    assert result.output == "VÁLIDO"


def test_tampered_certificate_field_is_invalid():
    cert = certificates.issue_certificate("Alice", 17, 3233, "Root CA", ROOT["d"], ROOT["n"])
    sig = cert.steps[-1].extra["signature"]
    # Verifying with a different subject name than what was actually signed:
    result = certificates.verify_certificate(
        "Mallory", "Root CA", 17, 3233, "2026-01-01", "2027-01-01", sig, ROOT["e"], ROOT["n"]
    )
    assert result.output == "INVÁLIDO"


def test_three_level_chain_all_valid():
    result = certificates.demo_chain()
    assert result.output == "Cadena completa VÁLIDA"
    assert result.steps[0].ok is True
