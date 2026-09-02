"""Simplified digital certificates: a certificate is a statement ("this public
key belongs to this subject") signed by an issuer's private key -- exactly the
same sign/verify machinery as app.algorithms.asymmetric.digital_signature,
applied to the concatenation of the certificate's fields instead of a free-text
message. Validity dates are plain text here (no real date-range enforcement) to
keep the scope on the trust/signature mechanics, which is the actual point.
"""
from __future__ import annotations

from app.algorithms.asymmetric.digital_signature import _hash_reduced
from app.core.numeric_utils import mod_pow_steps
from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "pki"
ALGORITHM = "certificates"


def _tbs(subject: str, issuer: str, subject_e: int, subject_n: int, valid_from: str, valid_to: str) -> str:
    """'To be signed' -- the canonical string of certificate fields that gets hashed and signed."""
    return f"subject={subject}|issuer={issuer}|pubkey=({subject_e},{subject_n})|valid={valid_from}..{valid_to}"


def issue_certificate(
    subject: str, subject_e: int, subject_n: int,
    issuer: str, issuer_d: int, issuer_n: int,
    valid_from: str = "2026-01-01", valid_to: str = "2027-01-01",
) -> AlgorithmRunResult:
    tbs = _tbs(subject, issuer, subject_e, subject_n, valid_from, valid_to)
    hex_digest, full_int, reduced = _hash_reduced(tbs, issuer_n)
    sig, rows = mod_pow_steps(reduced, issuer_d, issuer_n)

    steps = [
        step(
            1,
            "Armar el certificado (campos por firmar)",
            f"Se concatenan los campos del certificado en un string canónico: {tbs}",
        ),
        step(
            2,
            "Hashear y reducir mod n del emisor",
            f"SHA-256(campos) = {hex_digest}, reducido mod n_emisor={issuer_n}: {reduced}.",
        ),
        step(
            3,
            f"Firmar con la llave privada de {issuer}",
            f"El emisor ({issuer}) firma con su propia llave privada (d={issuer_d}, n={issuer_n}). "
            + ("Como el emisor es el mismo sujeto, este certificado es autofirmado." if subject == issuer else
               f"{issuer} está vouching for (dando fe de) la identidad de {subject}."),
            formula=f"firma = {reduced}^{issuer_d} mod {issuer_n} = {sig}",
            columns=["Bit del exponente", "resultado^2 mod n", "cuadrado", "multiplicar?", "nuevo resultado"],
            rows=rows,
            extra={"signature": sig},
        ),
    ]

    output = f"subject={subject}; issuer={issuer}; pubkey=({subject_e},{subject_n}); firma={sig}"

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="issue",
        input_summary={"text": tbs, "subject": subject, "issuer": issuer},
        output=output, output_label="Certificado emitido", steps=steps,
        error=None,
    )


def verify_certificate(
    subject: str, issuer: str, subject_e: int, subject_n: int,
    valid_from: str, valid_to: str, signature: int,
    issuer_e: int, issuer_n: int,
) -> AlgorithmRunResult:
    tbs = _tbs(subject, issuer, subject_e, subject_n, valid_from, valid_to)
    hex_digest, full_int, expected = _hash_reduced(tbs, issuer_n)
    recovered, rows = mod_pow_steps(signature, issuer_e, issuer_n)

    matches = recovered == expected
    steps = [
        step(1, "Reconstruir los campos del certificado", f"Campos: {tbs}"),
        step(2, "Recalcular el hash reducido mod n del emisor", f"SHA-256(campos) mod n_emisor = {expected}"),
        step(
            3,
            f"Deshacer la firma con la llave pública de {issuer}",
            f"firma^e_emisor mod n_emisor = {signature}^{issuer_e} mod {issuer_n} = {recovered}",
            columns=["Bit del exponente", "resultado^2 mod n", "cuadrado", "multiplicar?", "nuevo resultado"],
            rows=rows,
        ),
        step(
            4,
            "Comparar",
            (f"Coinciden ({expected} == {recovered}): el certificado es válido y realmente fue emitido "
             f"por {issuer}." if matches else
             f"NO coinciden ({expected} != {recovered}): el certificado NO es válido (fue alterado, o "
             "no fue firmado por la llave privada correspondiente a esta llave pública del emisor)."),
            ok=matches,
        ),
    ]

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="verify",
        input_summary={"text": tbs, "subject": subject, "issuer": issuer},
        output="VÁLIDO" if matches else "INVÁLIDO",
        output_label="Resultado de la verificación", steps=steps,
    )


def demo_chain() -> AlgorithmRunResult:
    """Root CA (self-signed) -> Intermediate (signed by Root) -> End-entity
    (signed by Intermediate), verifying every link. Keypairs below were each
    verified independently (see tests/algorithms/test_certificates.py)."""
    root = {"name": "Root CA", "e": 17, "d": 3853, "n": 66013}
    intermediate = {"name": "Intermedia CA", "e": 17, "d": 2753, "n": 3233}
    end_entity = {"name": "usuario@ejemplo.com", "e": 17, "d": 3953, "n": 11413}

    root_cert = issue_certificate(root["name"], root["e"], root["n"], root["name"], root["d"], root["n"])
    inter_cert = issue_certificate(intermediate["name"], intermediate["e"], intermediate["n"], root["name"], root["d"], root["n"])
    end_cert = issue_certificate(end_entity["name"], end_entity["e"], end_entity["n"], intermediate["name"], intermediate["d"], intermediate["n"])

    root_sig = root_cert.steps[-1].extra["signature"]
    inter_sig = inter_cert.steps[-1].extra["signature"]
    end_sig = end_cert.steps[-1].extra["signature"]

    root_verify = verify_certificate(root["name"], root["name"], root["e"], root["n"], "2026-01-01", "2027-01-01", root_sig, root["e"], root["n"])
    inter_verify = verify_certificate(intermediate["name"], root["name"], intermediate["e"], intermediate["n"], "2026-01-01", "2027-01-01", inter_sig, root["e"], root["n"])
    end_verify = verify_certificate(end_entity["name"], intermediate["name"], end_entity["e"], end_entity["n"], "2026-01-01", "2027-01-01", end_sig, intermediate["e"], intermediate["n"])

    chain_step = step(
        1,
        "Cadena de confianza de 3 niveles",
        f"{root['name']} se autofirma (raíz de confianza). {root['name']} firma el certificado de "
        f"{intermediate['name']}. {intermediate['name']} firma el certificado de {end_entity['name']}. "
        "Cada eslabón se verifica con la llave pública del nivel anterior.",
        columns=["Certificado", "Firmado por", "Verificado con", "Resultado"],
        rows=[
            [root["name"], f"{root['name']} (autofirmado)", f"llave pública de {root['name']}", root_verify.output],
            [intermediate["name"], root["name"], f"llave pública de {root['name']}", inter_verify.output],
            [end_entity["name"], intermediate["name"], f"llave pública de {intermediate['name']}", end_verify.output],
        ],
        ok=(root_verify.output == "VÁLIDO" and inter_verify.output == "VÁLIDO" and end_verify.output == "VÁLIDO"),
    )

    all_valid = chain_step.ok
    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="chain",
        input_summary={"text": "cadena de 3 niveles"},
        output="Cadena completa VÁLIDA" if all_valid else "Cadena INVÁLIDA",
        output_label="Resultado de la cadena", steps=[chain_step],
    )
