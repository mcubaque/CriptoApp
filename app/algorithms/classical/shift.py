"""Shift cipher (generalized Caesar): e_K(x) = (x + K) mod 26.
Reading reference: wewillmeetatmidnight + K=11 -> HPHTWWXPPELEXTOYTRSE
"""
from __future__ import annotations

from app.algorithms.classical.frequency import (
    english_likeness_score,
    frequency_chart,
    frequency_table,
    most_frequent_letters,
)
from app.core.step_trace import AlgorithmRunResult, step
from app.core.text_utils import ALPHABET_SIZE, int_to_letter, letter_to_int, normalize_text

FAMILY = "classical"
ALGORITHM = "shift"


def _normalize_step(idx: int, raw: str, cleaned: str) -> tuple[int, list]:
    steps = []
    if raw.upper() != cleaned and any(not ch.isalpha() for ch in raw):
        steps.append(
            step(
                idx,
                "Normalizar el texto",
                "Se pasa todo a mayúsculas y se eliminan espacios/signos: solo importan las letras A-Z.",
                extra={"before": raw, "after": cleaned},
            )
        )
        idx += 1
    return idx, steps


def encrypt(plaintext: str, key: int) -> AlgorithmRunResult:
    key = key % ALPHABET_SIZE
    cleaned = normalize_text(plaintext)
    idx = 1
    steps = []
    n_idx, norm_steps = _normalize_step(idx, plaintext, cleaned)
    steps += norm_steps
    idx = n_idx

    rows = []
    out_chars = []
    for ch in cleaned:
        x = letter_to_int(ch)
        summed = x + key
        y = summed % ALPHABET_SIZE
        out_chars.append(int_to_letter(y))
        rows.append([ch, x, f"{x} + {key} = {summed}", f"{summed} mod 26 = {y}", int_to_letter(y)])
    ciphertext = "".join(out_chars)

    steps.append(
        step(
            idx,
            "Cifrar letra por letra",
            f"Cada letra x se transforma con e_K(x) = (x + {key}) mod 26.",
            formula=f"e_K(x) = (x + {key}) mod 26",
            columns=["Letra", "x", "x + K", "mod 26", "Cifrada"],
            rows=rows,
        )
    )

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="encrypt",
        input_summary={"text": plaintext, "key": key},
        output=ciphertext,
        output_label="Texto cifrado",
        steps=steps,
    )


def decrypt(ciphertext: str, key: int) -> AlgorithmRunResult:
    key = key % ALPHABET_SIZE
    cleaned = normalize_text(ciphertext)
    idx = 1
    steps = []
    n_idx, norm_steps = _normalize_step(idx, ciphertext, cleaned)
    steps += norm_steps
    idx = n_idx

    rows = []
    out_chars = []
    for ch in cleaned:
        y = letter_to_int(ch)
        diff = y - key
        x = diff % ALPHABET_SIZE
        out_chars.append(int_to_letter(x))
        rows.append([ch, y, f"{y} - {key} = {diff}", f"{diff} mod 26 = {x}", int_to_letter(x)])
    plaintext = "".join(out_chars)

    steps.append(
        step(
            idx,
            "Descifrar letra por letra",
            f"Cada letra y se transforma con d_K(y) = (y - {key}) mod 26.",
            formula=f"d_K(y) = (y - {key}) mod 26",
            columns=["Letra", "y", "y - K", "mod 26", "Plana"],
            rows=rows,
        )
    )

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="decrypt",
        input_summary={"text": ciphertext, "key": key},
        output=plaintext,
        output_label="Texto plano",
        steps=steps,
    )


def crack_bruteforce(ciphertext: str) -> AlgorithmRunResult:
    cleaned = normalize_text(ciphertext)
    rows = []
    candidates = []
    for k in range(ALPHABET_SIZE):
        out_chars = [int_to_letter((letter_to_int(ch) - k) % ALPHABET_SIZE) for ch in cleaned]
        candidate = "".join(out_chars)
        score = english_likeness_score(candidate)
        rows.append([k, candidate, score])
        candidates.append((k, candidate, score))

    best_k, best_candidate, best_score = max(candidates, key=lambda c: c[2])

    steps = [
        step(
            1,
            "Probar las 26 llaves posibles",
            "Como el espacio de llaves es tan pequeño (Z26), probamos todas y calculamos un puntaje "
            "de 'parecido al inglés' (digramas/trigramas/palabras comunes) para cada candidato.",
            columns=["K", "Texto candidato", "Puntaje"],
            rows=rows,
        ),
        step(
            2,
            "Elegir el mejor candidato",
            f"La llave K={best_k} produce el texto con mayor puntaje de parecido al inglés.",
            extra={"best_key": best_k, "score": best_score},
        ),
    ]

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="crack",
        input_summary={"ciphertext": ciphertext, "mode": "bruteforce"},
        output=best_candidate,
        output_label="Texto plano candidato",
        steps=steps,
    )


def crack_frequency_hypothesis(
    ciphertext: str, cipher_letter: str, plain_letter: str
) -> AlgorithmRunResult:
    """Interactive mode: the user hypothesizes that one specific cipher letter
    corresponds to one specific plain letter (usually the most frequent cipher
    letter -> 'E'), and we solve directly for K."""
    cleaned = normalize_text(ciphertext)
    cipher_letter = cipher_letter.upper()
    plain_letter = plain_letter.upper()

    freq_step = step(
        1,
        "Contar frecuencias del texto cifrado",
        "Contamos cuántas veces aparece cada letra en el criptograma.",
        columns=frequency_table(cleaned).columns,
        rows=frequency_table(cleaned).rows,
        extra={"most_frequent": most_frequent_letters(cleaned)},
        chart=frequency_chart(cleaned),
    )

    y = letter_to_int(cipher_letter)
    x = letter_to_int(plain_letter)
    key = (y - x) % ALPHABET_SIZE

    hyp_step = step(
        2,
        "Plantear la hipótesis",
        f"Suponemos que la letra cifrada '{cipher_letter}' corresponde a la letra plana "
        f"'{plain_letter}'. Como e_K(x) = x + K, despejamos K = (y - x) mod 26.",
        formula=f"K = ({y} - {x}) mod 26 = {key}",
    )

    out_chars = [int_to_letter((letter_to_int(ch) - key) % ALPHABET_SIZE) for ch in cleaned]
    candidate = "".join(out_chars)
    score = english_likeness_score(candidate)

    result_step = step(
        3,
        "Descifrar con la llave obtenida",
        f"Con K={key} descifra el criptograma completo y evaluamos si el resultado tiene sentido "
        f"(puntaje de parecido al inglés: {score}).",
        extra={"candidate": candidate, "score": score, "key": key},
        ok=score > 0,
    )

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="crack",
        input_summary={
            "ciphertext": ciphertext,
            "mode": "frequency",
            "cipher_letter": cipher_letter,
            "plain_letter": plain_letter,
        },
        output=candidate,
        output_label="Texto plano candidato",
        steps=[freq_step, hyp_step, result_step],
    )
