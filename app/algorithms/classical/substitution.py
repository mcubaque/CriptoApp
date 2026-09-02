"""Monoalphabetic substitution cipher: key is a full permutation of the
26-letter alphabet. e_K(x) = key[index(x)]; d_K(y) = index_of(y, key).
Reading reference: table-based example, MGZVYZLGHC... -> thisciphertext...
"""
from __future__ import annotations

from app.algorithms.classical.frequency import (
    COMMON_DIGRAMS,
    COMMON_TRIGRAMS,
    ENGLISH_FREQUENCY_ORDER,
    english_likeness_score,
    frequency_chart,
    frequency_table,
    most_frequent_letters,
)
from app.core.step_trace import AlgorithmRunResult, step
from app.core.text_utils import ALPHABET, normalize_text

FAMILY = "classical"
ALGORITHM = "substitution"


def _validate_key(key: str) -> str | None:
    key = key.upper()
    if len(key) != 26:
        return f"La llave debe tener exactamente 26 letras (tiene {len(key)})."
    if set(key) != set(ALPHABET):
        return "La llave debe ser una permutación de A-Z, sin letras repetidas ni faltantes."
    return None


def encrypt(plaintext: str, key: str) -> AlgorithmRunResult:
    cleaned = normalize_text(plaintext)
    key = key.upper()
    error = _validate_key(key)
    if error:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="encrypt",
            input_summary={"text": plaintext, "key": key}, output=None,
            output_label="Texto cifrado",
            steps=[step(1, "Validar la llave", error, ok=False)], error=error,
        )

    rows = [[a, key[i]] for i, a in enumerate(ALPHABET)]
    out_chars = [key[ALPHABET.index(ch)] for ch in cleaned]
    ciphertext = "".join(out_chars)

    steps = [
        step(1, "Tabla de sustitución", "Cada letra del alfabeto se reemplaza según la llave (una permutación de 26 letras).",
             columns=["Plana", "Cifrada"], rows=rows),
        step(2, "Aplicar la sustitución al texto", "Se reemplaza cada letra del texto por su equivalente en la tabla.",
             extra={"before": cleaned, "after": ciphertext}),
    ]

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="encrypt",
        input_summary={"text": plaintext, "key": key}, output=ciphertext,
        output_label="Texto cifrado", steps=steps,
    )


def decrypt(ciphertext: str, key: str) -> AlgorithmRunResult:
    cleaned = normalize_text(ciphertext)
    key = key.upper()
    error = _validate_key(key)
    if error:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="decrypt",
            input_summary={"text": ciphertext, "key": key}, output=None,
            output_label="Texto plano",
            steps=[step(1, "Validar la llave", error, ok=False)], error=error,
        )

    rows = [[a, key[i]] for i, a in enumerate(ALPHABET)]
    out_chars = [ALPHABET[key.index(ch)] for ch in cleaned]
    plaintext = "".join(out_chars)

    steps = [
        step(1, "Tabla de sustitución (inversa)", "Para descifrar, buscamos en la tabla qué letra plana produce cada letra cifrada.",
             columns=["Plana", "Cifrada"], rows=rows),
        step(2, "Aplicar la sustitución inversa al texto", "Se reemplaza cada letra cifrada por la letra plana correspondiente.",
             extra={"before": cleaned, "after": plaintext}),
    ]

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="decrypt",
        input_summary={"text": ciphertext, "key": key}, output=plaintext,
        output_label="Texto plano", steps=steps,
    )


def crack_interactive(ciphertext: str, mapping: dict[str, str]) -> AlgorithmRunResult:
    """mapping: {cipher_letter: plain_letter} partial or complete guesses so far.
    Cipher letters without a guess yet are shown unresolved (lowercase, literal),
    mirroring the reading's progressive-reveal style ('ocanaJatePPeJeno...')."""
    cleaned = normalize_text(ciphertext)
    mapping = {k.upper(): v.upper() for k, v in mapping.items()}

    freq_step = step(
        1,
        "Contar frecuencias y comparar con digramas/trigramas comunes",
        "Las letras cifradas más frecuentes probablemente son E, T, A... Los patrones repetidos "
        "pueden coincidir con digramas/trigramas comunes del inglés.",
        columns=frequency_table(cleaned).columns,
        rows=frequency_table(cleaned).rows,
        extra={"common_digrams": COMMON_DIGRAMS[:10], "common_trigrams": COMMON_TRIGRAMS[:6]},
        chart=frequency_chart(cleaned),
    )

    reveal_chars = []
    rows = []
    for ch in cleaned:
        if ch in mapping:
            reveal_chars.append(mapping[ch])
        else:
            reveal_chars.append(ch.lower())
    candidate = "".join(reveal_chars)

    mapping_rows = [[c, p] for c, p in sorted(mapping.items())]
    score = english_likeness_score(candidate.upper())

    hyp_step = step(
        2,
        "Hipótesis acumuladas",
        f"Van {len(mapping)} de 26 letras asignadas. Las letras sin asignar se muestran en minúscula "
        "(sin descifrar todavía), igual que en el proceso manual de la lectura.",
        columns=["Cifrada", "Plana asignada"] if mapping_rows else None,
        rows=mapping_rows if mapping_rows else None,
        extra={"candidate": candidate, "score": score},
    )

    complete = len(mapping) == 26 and len(set(mapping.values())) == 26

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="crack",
        input_summary={"ciphertext": ciphertext, "mapping": mapping},
        output=candidate,
        output_label="Texto plano candidato" if not complete else "Texto plano",
        steps=[freq_step, hyp_step],
    )


def crack_auto(ciphertext: str, top_n: int = 6) -> AlgorithmRunResult:
    """Convenience 'auto-solve': greedily maps the top-N most frequent cipher
    letters to the top-N most frequent English letters (ETAOIN...). Not a
    dictionary-backed solver, just the same frequency heuristic a human would
    try first -- the trace shows exactly which guesses were made, it's not a
    black box."""
    cleaned = normalize_text(ciphertext)
    top_cipher = most_frequent_letters(cleaned, top_n=top_n)
    auto_mapping = {c: p for c, p in zip(top_cipher, ENGLISH_FREQUENCY_ORDER[:top_n])}

    result = crack_interactive(ciphertext, auto_mapping)
    result.steps.insert(
        0,
        step(
            0,
            "Auto-resolver: generar hipótesis por frecuencia",
            f"Se asignan las {len(auto_mapping)} letras cifradas más frecuentes a las letras más "
            "frecuentes del inglés en ese mismo orden (E, T, A, O, I, N...). Es una conjetura inicial, "
            "no siempre es correcta letra por letra.",
            columns=["Cifrada", "Plana (conjetura)"],
            rows=[[c, p] for c, p in auto_mapping.items()],
        ),
    )
    for i, s in enumerate(result.steps):
        s.index = i + 1
    return result
