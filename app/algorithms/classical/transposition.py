"""Columnar transposition cipher: split into blocks of size m, permute
positions within each block according to key pi (1-indexed): y_i = x_pi(i).
Reading reference: m=6, worked example with 'shesel|lsseas|...' blocks.
"""
from __future__ import annotations

from app.core.step_trace import AlgorithmRunResult, step
from app.core.text_utils import chunk, normalize_text

FAMILY = "classical"
ALGORITHM = "transposition"


def _validate_key(key: list[int], m: int) -> str | None:
    if m == 0:
        return "La llave no puede estar vacía."
    if sorted(key) != list(range(1, m + 1)):
        return f"La llave debe ser una permutación de 1..{m}, sin repetidos ni huecos (recibido: {key})."
    return None


def _inverse(key: list[int]) -> list[int]:
    m = len(key)
    inv = [0] * m
    for i, p in enumerate(key, start=1):
        inv[p - 1] = i
    return inv


def encrypt(plaintext: str, key: list[int]) -> AlgorithmRunResult:
    cleaned = normalize_text(plaintext)
    m = len(key)
    error = _validate_key(key, m)
    if error:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="encrypt",
            input_summary={"text": plaintext, "key": key}, output=None,
            output_label="Texto cifrado",
            steps=[step(1, "Validar la llave", error, ok=False)], error=error,
        )

    blocks = chunk(cleaned, m)
    rows = []
    out_blocks = []
    for block in blocks:
        permuted = "".join(block[key[i] - 1] for i in range(m))
        out_blocks.append(permuted)
        rows.append([block, " ".join(str(k) for k in key), permuted])
    ciphertext = "".join(out_blocks)

    steps = [
        step(
            1,
            f"Dividir el texto en bloques de tamaño {m}",
            "El texto normalizado se corta en bloques de tamaño m (se rellena el último con 'X' si falta).",
            extra={"blocks": blocks},
        ),
        step(
            2,
            "Permutar cada bloque según la llave",
            f"Para cada bloque, la posición i del cifrado toma la letra en la posición π(i) del bloque plano. π = {key}.",
            formula="y_i = x_{π(i)}",
            columns=["Bloque plano", "π", "Bloque cifrado"],
            rows=rows,
        ),
    ]

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="encrypt",
        input_summary={"text": plaintext, "key": key}, output=ciphertext,
        output_label="Texto cifrado", steps=steps,
    )


def decrypt(ciphertext: str, key: list[int]) -> AlgorithmRunResult:
    cleaned = normalize_text(ciphertext)
    m = len(key)
    error = _validate_key(key, m)
    if error:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="decrypt",
            input_summary={"text": ciphertext, "key": key}, output=None,
            output_label="Texto plano",
            steps=[step(1, "Validar la llave", error, ok=False)], error=error,
        )

    inv = _inverse(key)
    blocks = chunk(cleaned, m, pad_char="")
    rows = []
    out_blocks = []
    for block in blocks:
        if len(block) < m:
            continue
        restored = "".join(block[inv[i] - 1] for i in range(m))
        out_blocks.append(restored)
        rows.append([block, " ".join(str(k) for k in inv), restored])
    plaintext = "".join(out_blocks)

    steps = [
        step(
            1,
            "Calcular la permutación inversa π⁻¹",
            f"π = {key}  →  π⁻¹ = {inv}",
        ),
        step(
            2,
            "Deshacer la permutación en cada bloque",
            "Para cada bloque cifrado, la posición j del texto plano toma la letra en la posición π⁻¹(j).",
            formula="x_j = y_{π⁻¹(j)}",
            columns=["Bloque cifrado", "π⁻¹", "Bloque plano"],
            rows=rows,
        ),
    ]

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="decrypt",
        input_summary={"text": ciphertext, "key": key}, output=plaintext,
        output_label="Texto plano", steps=steps,
    )
