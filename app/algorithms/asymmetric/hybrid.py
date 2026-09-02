"""Hybrid cryptography: RSA (asymmetric) encrypts a random/short-lived S-AES
session key, then S-AES (symmetric, fast) encrypts the actual message in
16-bit blocks under that session key. This is exactly the shape of real
protocols like TLS: asymmetric crypto is slow but solves key distribution;
symmetric crypto is fast but needs a shared secret -- hybrid schemes get both.

Reuses app.algorithms.asymmetric.rsa and app.algorithms.symmetric_modern.saes
directly and re-exposes their own step traces (so "cripto híbrida" isn't a new
kind of math, just these two already-built pieces composed together).

En el mundo real: la llave de sesión se genera aleatoriamente para cada mensaje
(nunca se reusa), y el mensaje se cifra con un modo de operación real (no ECB
bloque-por-bloque como aquí) para no filtrar patrones repetidos.
"""
from __future__ import annotations

from app.algorithms.asymmetric import rsa
from app.algorithms.symmetric_modern import saes
from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "asymmetric"
ALGORITHM = "hybrid"


def _text_to_blocks(text: str) -> list[str]:
    byte_values = [ord(c) & 0xFF for c in text]
    if len(byte_values) % 2 == 1:
        byte_values.append(0)
    blocks = []
    for i in range(0, len(byte_values), 2):
        blocks.append(format(byte_values[i], "08b") + format(byte_values[i + 1], "08b"))
    return blocks


def _blocks_to_text(blocks: list[str]) -> str:
    chars = []
    for block in blocks:
        b1, b2 = int(block[:8], 2), int(block[8:], 2)
        if b1:
            chars.append(chr(b1))
        if b2:
            chars.append(chr(b2))
    return "".join(chars)


def _validate_bits(value: str, length: int, label: str) -> str | None:
    value = value.strip()
    if len(value) != length or any(c not in "01" for c in value):
        return f"{label} debe ser una cadena de exactamente {length} bits (solo 0s y 1s)."
    return None


def encrypt(message: str, session_key16: str, rsa_e: int, rsa_n: int) -> AlgorithmRunResult:
    session_key16 = session_key16.strip()
    err = _validate_bits(session_key16, 16, "La llave de sesión")
    if err:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="encrypt",
            input_summary={"text": message, "session_key16": session_key16, "e": rsa_e, "n": rsa_n},
            output=None, output_label="Resultado",
            steps=[step(1, "Validar la llave de sesión", err, ok=False)], error=err,
        )

    key_int = int(session_key16, 2)
    idx = 1
    steps = [
        step(
            idx,
            "Fase 1 de 2 -- cifrar la llave de sesión con RSA",
            f"La llave de sesión S-AES ({session_key16} = {key_int} en decimal) se cifra con la llave "
            f"pública del destinatario (e={rsa_e}, n={rsa_n}). Solo quien tenga la llave privada podrá "
            "recuperarla.",
        )
    ]
    idx += 1

    rsa_res = rsa.encrypt(key_int, rsa_e, rsa_n)
    for s in rsa_res.steps:
        s.index = idx
        idx += 1
        steps.append(s)

    if not rsa_res.ok:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="encrypt",
            input_summary={"text": message, "session_key16": session_key16, "e": rsa_e, "n": rsa_n},
            output=None, output_label="Resultado", steps=steps, error=rsa_res.error,
        )

    encrypted_key = rsa_res.output

    steps.append(
        step(
            idx,
            "Fase 2 de 2 -- cifrar el mensaje con S-AES",
            f"El mensaje se trocea en bloques de 16 bits (2 caracteres cada uno) y cada bloque se cifra "
            f"con S-AES usando la llave de sesión {session_key16}.",
        )
    )
    idx += 1

    blocks = _text_to_blocks(message)
    cipher_blocks = []
    rows = []
    first_block_steps = []
    for i, block in enumerate(blocks):
        r = saes.encrypt(block, session_key16)
        cipher_blocks.append(r.output)
        rows.append([i + 1, block, r.output])
        if i == 0:
            first_block_steps = r.steps

    for s in first_block_steps:
        s.index = idx
        s.title = f"[Bloque 1] {s.title}"
        idx += 1
        steps.append(s)

    steps.append(
        step(
            idx,
            "Todos los bloques cifrados",
            "El mismo proceso mostrado arriba para el bloque 1 se repite exactamente igual para cada "
            "bloque del mensaje.",
            columns=["Bloque #", "Texto plano (16 bits)", "Cifrado (16 bits)"],
            rows=rows,
        )
    )

    bundle = f"llave_cifrada={encrypted_key} | bloques={'|'.join(cipher_blocks)}"

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="encrypt",
        input_summary={"text": message, "session_key16": session_key16, "e": rsa_e, "n": rsa_n},
        output=bundle,
        output_label="Paquete híbrido (llave cifrada + bloques cifrados)",
        steps=steps,
    )


def decrypt(encrypted_key: int, cipher_blocks: str, rsa_d: int, rsa_n: int) -> AlgorithmRunResult:
    idx = 1
    steps = [
        step(
            idx,
            "Fase 1 de 2 -- descifrar la llave de sesión con RSA",
            f"Se usa la llave privada (d={rsa_d}, n={rsa_n}) para recuperar la llave de sesión a partir "
            f"del número cifrado {encrypted_key}.",
        )
    ]
    idx += 1

    rsa_res = rsa.decrypt(encrypted_key, rsa_d, rsa_n)
    for s in rsa_res.steps:
        s.index = idx
        idx += 1
        steps.append(s)

    if not rsa_res.ok:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="decrypt",
            input_summary={"encrypted_key": encrypted_key, "cipher_blocks": cipher_blocks, "d": rsa_d, "n": rsa_n},
            output=None, output_label="Resultado", steps=steps, error=rsa_res.error,
        )

    key_int = int(rsa_res.output)
    session_key16 = format(key_int, "016b")
    steps.append(
        step(
            idx,
            "Llave de sesión recuperada",
            f"m = {key_int} en decimal -> {session_key16} en binario de 16 bits.",
        )
    )
    idx += 1

    steps.append(
        step(
            idx,
            "Fase 2 de 2 -- descifrar cada bloque con S-AES",
            f"Cada bloque cifrado se descifra con S-AES usando la llave de sesión recuperada, {session_key16}.",
        )
    )
    idx += 1

    blocks = [b.strip() for b in cipher_blocks.split("|") if b.strip()]
    plain_blocks = []
    rows = []
    first_block_steps = []
    for i, block in enumerate(blocks):
        err = _validate_bits(block, 16, f"El bloque #{i + 1}")
        if err:
            return AlgorithmRunResult(
                ok=False, family=FAMILY, algorithm=ALGORITHM, operation="decrypt",
                input_summary={"encrypted_key": encrypted_key, "cipher_blocks": cipher_blocks, "d": rsa_d, "n": rsa_n},
                output=None, output_label="Resultado",
                steps=steps + [step(idx, "Validar bloques", err, ok=False)], error=err,
            )
        r = saes.decrypt(block, session_key16)
        plain_blocks.append(r.output)
        rows.append([i + 1, block, r.output])
        if i == 0:
            first_block_steps = r.steps

    for s in first_block_steps:
        s.index = idx
        s.title = f"[Bloque 1] {s.title}"
        idx += 1
        steps.append(s)

    steps.append(
        step(
            idx,
            "Todos los bloques descifrados",
            "El mismo proceso mostrado arriba para el bloque 1 se repite para cada bloque.",
            columns=["Bloque #", "Cifrado (16 bits)", "Plano (16 bits)"],
            rows=rows,
        )
    )

    message = _blocks_to_text(plain_blocks)

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="decrypt",
        input_summary={"encrypted_key": encrypted_key, "cipher_blocks": cipher_blocks, "d": rsa_d, "n": rsa_n},
        output=message,
        output_label="Mensaje descifrado",
        steps=steps,
    )
