"""Affine cipher: e_K(x) = (a*x + b) mod 26, K=(a,b), requires gcd(a,26)=1.
Reading reference: attackhasbeenalreadydone with (a,b)=(7,2) -> CFFCQUYCYJEEPCBRECXXPE
"""
from __future__ import annotations

from app.algorithms.classical.frequency import (
    english_likeness_score,
    frequency_chart,
    frequency_table,
    most_frequent_letters,
)
from app.core.numeric_utils import gcd, modinv
from app.core.step_trace import AlgorithmRunResult, step
from app.core.text_utils import ALPHABET_SIZE, int_to_letter, letter_to_int, normalize_text

FAMILY = "classical"
ALGORITHM = "affine"


def is_legal_key(a: int) -> bool:
    return gcd(a, ALPHABET_SIZE) == 1


def encrypt(plaintext: str, a: int, b: int) -> AlgorithmRunResult:
    cleaned = normalize_text(plaintext)

    if not is_legal_key(a):
        return AlgorithmRunResult(
            ok=False,
            family=FAMILY,
            algorithm=ALGORITHM,
            operation="encrypt",
            input_summary={"text": plaintext, "a": a, "b": b},
            output=None,
            output_label="Texto cifrado",
            steps=[
                step(
                    1,
                    "Verificar que la llave sea legal",
                    f"gcd(a, 26) = gcd({a}, 26) = {gcd(a, ALPHABET_SIZE)} ≠ 1. "
                    "La llave no es invertible módulo 26, así que no se puede usar: "
                    "dos letras distintas cifrarían al mismo valor y no habría forma de descifrar sin ambigüedad.",
                    ok=False,
                )
            ],
            error=f"Llave ilegal: gcd({a}, 26) = {gcd(a, ALPHABET_SIZE)} ≠ 1",
        )

    rows = []
    out_chars = []
    for ch in cleaned:
        x = letter_to_int(ch)
        prod = a * x
        summed = prod + b
        y = summed % ALPHABET_SIZE
        out_chars.append(int_to_letter(y))
        rows.append([ch, x, f"{a}·{x} = {prod}", f"{prod} + {b} = {summed}", f"mod 26 = {y}", int_to_letter(y)])
    ciphertext = "".join(out_chars)

    steps = [
        step(
            1,
            "Verificar que la llave sea legal",
            f"gcd(a, 26) = gcd({a}, 26) = 1, así que a={a} es invertible módulo 26 y la llave es válida.",
        ),
        step(
            2,
            "Cifrar letra por letra",
            f"Cada letra x se transforma con e_K(x) = ({a}x + {b}) mod 26.",
            formula=f"e_K(x) = ({a}x + {b}) mod 26",
            columns=["Letra", "x", "a·x", "+ b", "mod 26", "Cifrada"],
            rows=rows,
        ),
    ]

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="encrypt",
        input_summary={"text": plaintext, "a": a, "b": b},
        output=ciphertext,
        output_label="Texto cifrado",
        steps=steps,
    )


def decrypt(ciphertext: str, a: int, b: int) -> AlgorithmRunResult:
    cleaned = normalize_text(ciphertext)
    a_inv = modinv(a, ALPHABET_SIZE)

    if a_inv is None:
        return AlgorithmRunResult(
            ok=False,
            family=FAMILY,
            algorithm=ALGORITHM,
            operation="decrypt",
            input_summary={"text": ciphertext, "a": a, "b": b},
            output=None,
            output_label="Texto plano",
            steps=[
                step(
                    1,
                    "Verificar que la llave sea legal",
                    f"gcd(a, 26) = gcd({a}, 26) = {gcd(a, ALPHABET_SIZE)} ≠ 1, no existe inverso de a módulo 26.",
                    ok=False,
                )
            ],
            error=f"Llave ilegal: gcd({a}, 26) = {gcd(a, ALPHABET_SIZE)} ≠ 1",
        )

    rows = []
    out_chars = []
    for ch in cleaned:
        y = letter_to_int(ch)
        diff = y - b
        prod = a_inv * diff
        x = prod % ALPHABET_SIZE
        out_chars.append(int_to_letter(x))
        rows.append([ch, y, f"{y} - {b} = {diff}", f"{a_inv}·{diff} = {prod}", f"mod 26 = {x}", int_to_letter(x)])
    plaintext = "".join(out_chars)

    steps = [
        step(
            1,
            "Calcular el inverso de a módulo 26",
            f"a⁻¹ mod 26 = {a_inv}, ya que {a}·{a_inv} mod 26 = 1.",
        ),
        step(
            2,
            "Descifrar letra por letra",
            f"Cada letra y se transforma con d_K(y) = a⁻¹(y - {b}) mod 26.",
            formula=f"d_K(y) = {a_inv}(y - {b}) mod 26",
            columns=["Letra", "y", "y - b", "a⁻¹·(y-b)", "mod 26", "Plana"],
            rows=rows,
        ),
    ]

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="decrypt",
        input_summary={"text": ciphertext, "a": a, "b": b},
        output=plaintext,
        output_label="Texto plano",
        steps=steps,
    )


def crack_bruteforce(ciphertext: str) -> AlgorithmRunResult:
    cleaned = normalize_text(ciphertext)
    rows = []
    candidates = []
    for a in range(1, ALPHABET_SIZE):
        if not is_legal_key(a):
            continue
        a_inv = modinv(a, ALPHABET_SIZE)
        for b in range(ALPHABET_SIZE):
            out_chars = [
                int_to_letter((a_inv * (letter_to_int(ch) - b)) % ALPHABET_SIZE) for ch in cleaned
            ]
            candidate = "".join(out_chars)
            score = english_likeness_score(candidate)
            if score > 0:
                rows.append([a, b, candidate, score])
            candidates.append((a, b, candidate, score))

    rows.sort(key=lambda r: -r[3])
    best_a, best_b, best_candidate, best_score = max(candidates, key=lambda c: c[3])

    steps = [
        step(
            1,
            "Probar las 312 llaves legales (a,b)",
            "Hay 12 valores válidos de a (coprimos con 26) × 26 valores de b = 312 llaves. "
            "Se muestran solo las que obtuvieron puntaje de parecido al inglés mayor a 0.",
            columns=["a", "b", "Texto candidato", "Puntaje"],
            rows=rows[:15],
        ),
        step(
            2,
            "Elegir el mejor candidato",
            f"La llave (a={best_a}, b={best_b}) produce el texto con mayor puntaje.",
            extra={"best_a": best_a, "best_b": best_b, "score": best_score},
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
    ciphertext: str,
    cipher_letter_1: str,
    plain_letter_1: str,
    cipher_letter_2: str,
    plain_letter_2: str,
) -> AlgorithmRunResult:
    """Interactive mode mirroring the reading's iterative process: the user
    hypothesizes two (cipher-letter -> plain-letter) pairs, we solve the
    resulting 2x2 linear system mod 26 for (a,b), and validate legality."""
    cleaned = normalize_text(ciphertext)

    y1, x1 = letter_to_int(cipher_letter_1.upper()), letter_to_int(plain_letter_1.upper())
    y2, x2 = letter_to_int(cipher_letter_2.upper()), letter_to_int(plain_letter_2.upper())

    freq_step = step(
        1,
        "Contar frecuencias del texto cifrado",
        "Contamos cuántas veces aparece cada letra en el criptograma.",
        columns=frequency_table(cleaned).columns,
        rows=frequency_table(cleaned).rows,
        extra={"most_frequent": most_frequent_letters(cleaned)},
        chart=frequency_chart(cleaned),
    )

    hyp_step = step(
        2,
        "Plantear la hipótesis (dos ecuaciones)",
        f"Suponemos e_K({plain_letter_1.upper()})={cipher_letter_1.upper()} y "
        f"e_K({plain_letter_2.upper()})={cipher_letter_2.upper()}. Esto da el sistema:\n"
        f"{y1} = a·{x1} + b (mod 26)\n{y2} = a·{x2} + b (mod 26)",
        formula=f"{y1} = a·{x1} + b ,  {y2} = a·{x2} + b   (mod 26)",
    )

    dx = (x1 - x2) % ALPHABET_SIZE
    dx_inv = modinv(dx, ALPHABET_SIZE)

    if dx_inv is None:
        fail_step = step(
            3,
            "Resolver el sistema",
            f"x1 - x2 = {dx} mod 26 no tiene inverso (gcd({dx},26) ≠ 1). "
            "Con estas dos letras el sistema no se puede resolver de forma única; hay que probar otro par.",
            ok=False,
        )
        return AlgorithmRunResult(
            ok=False,
            family=FAMILY,
            algorithm=ALGORITHM,
            operation="crack",
            input_summary={
                "ciphertext": ciphertext,
                "mode": "frequency",
                "cipher_letter_1": cipher_letter_1,
                "plain_letter_1": plain_letter_1,
                "cipher_letter_2": cipher_letter_2,
                "plain_letter_2": plain_letter_2,
            },
            output=None,
            output_label="Texto plano candidato",
            steps=[freq_step, hyp_step, fail_step],
            error="Sistema sin solución única con este par de letras.",
        )

    a = ((y1 - y2) * dx_inv) % ALPHABET_SIZE
    b = (y1 - a * x1) % ALPHABET_SIZE

    solve_step = step(
        3,
        "Resolver el sistema para (a, b)",
        f"a = (y1 - y2)·(x1 - x2)⁻¹ mod 26 = ({y1}-{y2})·{dx_inv} mod 26 = {a}. "
        f"b = (y1 - a·x1) mod 26 = ({y1} - {a}·{x1}) mod 26 = {b}.",
        formula=f"a = {a}, b = {b}",
    )

    if not is_legal_key(a):
        legal_step = step(
            4,
            "Verificar legalidad de la llave",
            f"gcd(a, 26) = gcd({a}, 26) = {gcd(a, ALPHABET_SIZE)} ≠ 1. Llave ilegal, tal como pasa en la "
            "lectura con varias hipótesis fallidas antes de dar con la correcta. Hay que probar otra hipótesis.",
            ok=False,
        )
        return AlgorithmRunResult(
            ok=False,
            family=FAMILY,
            algorithm=ALGORITHM,
            operation="crack",
            input_summary={
                "ciphertext": ciphertext,
                "mode": "frequency",
                "cipher_letter_1": cipher_letter_1,
                "plain_letter_1": plain_letter_1,
                "cipher_letter_2": cipher_letter_2,
                "plain_letter_2": plain_letter_2,
            },
            output=None,
            output_label="Texto plano candidato",
            steps=[freq_step, hyp_step, solve_step, legal_step],
            error=f"Llave ilegal: a={a}, gcd({a},26)={gcd(a, ALPHABET_SIZE)}",
        )

    a_inv = modinv(a, ALPHABET_SIZE)
    out_chars = [int_to_letter((a_inv * (letter_to_int(ch) - b)) % ALPHABET_SIZE) for ch in cleaned]
    candidate = "".join(out_chars)
    score = english_likeness_score(candidate)

    result_step = step(
        4,
        "Descifrar con la llave obtenida",
        f"Llave legal (a={a}, b={b}). Descifrando el criptograma completo obtenemos el candidato "
        f"(puntaje de parecido al inglés: {score}).",
        extra={"candidate": candidate, "score": score, "a": a, "b": b},
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
            "cipher_letter_1": cipher_letter_1,
            "plain_letter_1": plain_letter_1,
            "cipher_letter_2": cipher_letter_2,
            "plain_letter_2": plain_letter_2,
        },
        output=candidate,
        output_label="Texto plano candidato",
        steps=[freq_step, hyp_step, solve_step, result_step],
    )
