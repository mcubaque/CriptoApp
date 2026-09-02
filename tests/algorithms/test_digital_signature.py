from app.algorithms.asymmetric import digital_signature

# Classic RSA keypair reused from test_rsa.py: p=61, q=53, e=17, d=2753, n=3233.
N = 3233
E = 17
D = 2753


def test_sign_then_verify_is_valid():
    signed = digital_signature.sign("hola mundo", D, N)
    result = digital_signature.verify("hola mundo", int(signed.output), E, N)
    assert result.output == "VÁLIDA"
    assert result.steps[-1].ok is True


def test_tampered_message_is_invalid():
    signed = digital_signature.sign("hola mundo", D, N)
    result = digital_signature.verify("hola mundO", int(signed.output), E, N)
    assert result.output == "INVÁLIDA"
    assert result.steps[-1].ok is False


def test_wrong_public_key_is_invalid():
    signed = digital_signature.sign("hola mundo", D, N)
    result = digital_signature.verify("hola mundo", int(signed.output), 7, N)
    assert result.output == "INVÁLIDA"
