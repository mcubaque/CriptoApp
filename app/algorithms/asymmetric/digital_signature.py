"""RSA digital signatures: sign with the private key (d,n), verify with the
public key (e,n). Reuses the same RSA machinery as app/algorithms/asymmetric/rsa.py.

Hashing uses Python's stdlib hashlib (SHA-256) -- unlike every other algorithm in
this app, we don't reimplement the hash internals by hand: SHA-256 has 64 rounds
and a nontrivial message schedule, disproportionate to trace step-by-step the way
S-DES/S-AES are (2 rounds, meant to be seen in full). See app/algorithms/authentication/
hash_demo.py for a dedicated, honest black-box exploration of hashing itself.

En el mundo real: n es mucho mayor que el hash de 256 bits, así que el hash nunca
se reduce mod n. Aquí n es pequeño para la demo, así que se reduce explícitamente.
"""
from __future__ import annotations

import hashlib

from app.core.numeric_utils import mod_pow_steps
from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "asymmetric"
ALGORITHM = "digital_signature"


def _hash_reduced(message: str, n: int) -> tuple[str, int, int]:
    hex_digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    full_int = int(hex_digest, 16)
    reduced = full_int % n
    return hex_digest, full_int, reduced


def sign(message: str, d: int, n: int) -> AlgorithmRunResult:
    hex_digest, full_int, reduced = _hash_reduced(message, n)

    hash_step = step(
        1,
        "Calcular el hash del mensaje (SHA-256)",
        f"hash = SHA-256('{message}') = {hex_digest}",
        formula=f"H(m) = {hex_digest}",
    )
    reduce_step = step(
        2,
        "Reducir el hash mod n",
        f"El hash es un número de 256 bits ({full_int}), mucho más grande que n={n}. "
        f"Lo reducimos: {full_int} mod {n} = {reduced}. "
        "(En RSA real n es mayor que el hash, así que este paso no haría falta.)",
        formula=f"H(m) mod n = {reduced}",
    )
    sig, rows = mod_pow_steps(reduced, d, n)
    sign_step = step(
        3,
        "Firmar: s = H(m)^d mod n",
        f"Se eleva el hash reducido a la potencia d (la llave privada) módulo n.",
        formula=f"s = {reduced}^{d} mod {n} = {sig}",
        columns=["Bit de d", "resultado^2 mod n", "cuadrado", "multiplicar por H(m)?", "nuevo resultado"],
        rows=rows,
    )

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="sign",
        input_summary={"text": message, "d": d, "n": n},
        output=str(sig),
        output_label="Firma (número)",
        steps=[hash_step, reduce_step, sign_step],
    )


def verify(message: str, signature: int, e: int, n: int) -> AlgorithmRunResult:
    hex_digest, full_int, expected = _hash_reduced(message, n)

    hash_step = step(
        1,
        "Calcular el hash del mensaje recibido (SHA-256)",
        f"hash = SHA-256('{message}') = {hex_digest}",
        formula=f"H(m) mod n = {expected}",
    )

    recovered, rows = mod_pow_steps(signature, e, n)
    recover_step = step(
        2,
        "Deshacer la firma: s^e mod n",
        "Se eleva la firma recibida a la potencia e (la llave pública del firmante) módulo n. "
        "Si el firmante realmente usó su llave privada d, esto debe recuperar el hash reducido.",
        formula=f"s^e mod n = {signature}^{e} mod {n} = {recovered}",
        columns=["Bit de e", "resultado^2 mod n", "cuadrado", "multiplicar por s?", "nuevo resultado"],
        rows=rows,
    )

    matches = recovered == expected
    compare_step = step(
        3,
        "Comparar",
        f"Hash recalculado del mensaje: {expected}. Valor recuperado de la firma: {recovered}. "
        + ("Coinciden: la firma es válida." if matches else "No coinciden: la firma NO es válida (mensaje alterado, firma incorrecta, o llave equivocada)."),
        ok=matches,
    )

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="verify",
        input_summary={"text": message, "signature": signature, "e": e, "n": n},
        output="VÁLIDA" if matches else "INVÁLIDA",
        output_label="Resultado de la verificación",
        steps=[hash_step, recover_step, compare_step],
    )
