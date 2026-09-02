"""Classic textbook attacks against small/misused RSA parameters. All three
reuse the same number-theory primitives as app/algorithms/asymmetric/rsa.py
(app/core/numeric_utils.py) -- nothing here is a new kind of arithmetic, just a
different way of combining gcd/modular-inverse/modular-exponentiation to break
RSA when a precondition is violated (n factorable, e's not independent, d too
small).

En el mundo real: estos ataques son la razón concreta detrás de reglas como
"nunca reuses el mismo n para distintos destinatarios" (módulo común) o "nunca
uses un exponente privado d pequeño para 'optimizar' el descifrado" (Wiener).
"""
from __future__ import annotations

import math

from app.core.numeric_utils import extended_gcd_steps, gcd, mod_pow_steps, modinv
from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "asymmetric"
ALGORITHM = "rsa_attacks"

MAX_FACTOR_N = 2_000_000


def factor_bruteforce(n: int) -> AlgorithmRunResult:
    if n < 4:
        msg = "n debe ser mayor a 3."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="factor",
            input_summary={"n": n}, output=None, output_label="Resultado",
            steps=[step(1, "Validar n", msg, ok=False)], error=msg,
        )
    if n > MAX_FACTOR_N:
        msg = f"n={n} es demasiado grande para factorizar por división de tanteo en esta demo (tope: {MAX_FACTOR_N:,})."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="factor",
            input_summary={"n": n}, output=None, output_label="Resultado",
            steps=[step(1, "Validar tamaño de n", msg, ok=False)], error=msg,
        )

    rows = []
    p = None
    divisor = 2
    limit = int(math.isqrt(n))
    while divisor <= limit:
        divides = n % divisor == 0
        if len(rows) < 25 or divides:
            rows.append([divisor, "SÍ" if divides else "no"])
        if divides:
            p = divisor
            break
        divisor += 1

    steps = [
        step(
            1,
            "Dividir n por tanteo hasta √n",
            f"Se prueba dividir n={n} entre 2, 3, 4, ... hasta √n ≈ {limit}. En cuanto un divisor da "
            "residuo 0, ya tenemos un factor.",
            columns=["Divisor probado", "¿Divide a n?"],
            rows=rows,
        )
    ]

    if p is None:
        msg = f"n={n} es primo (o el algoritmo no encontró factores hasta √n) -- no se puede factorizar en dos factores no triviales."
        steps.append(step(2, "Resultado", msg, ok=False))
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="factor",
            input_summary={"n": n}, output=None, output_label="Resultado", steps=steps, error=msg,
        )

    q = n // p
    phi = (p - 1) * (q - 1)
    steps.append(
        step(
            2,
            "Factores encontrados",
            f"n = {p} × {q}. Con esto, cualquiera puede calcular φ(n) = ({p}-1)({q}-1) = {phi} y, si "
            "conoce e, recuperar d exactamente igual que lo hizo el dueño legítimo de la llave. Esto es "
            "precisamente lo que RSA depende de que sea imposible en tiempo razonable para n grande.",
            extra={"p": p, "q": q, "phi": phi},
        )
    )

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="factor",
        input_summary={"n": n}, output=f"p={p}, q={q}", output_label="Factores de n", steps=steps,
    )


def _mod_pow_signed(base: int, exponent: int, n: int) -> tuple[int, list]:
    if exponent >= 0:
        return mod_pow_steps(base, exponent, n)
    inv = modinv(base, n)
    if inv is None:
        raise ValueError("La base no tiene inverso modular; no se puede aplicar exponente negativo.")
    return mod_pow_steps(inv, -exponent, n)


def common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> AlgorithmRunResult:
    g, a, b, euclid_rows = extended_gcd_steps(e1, e2)

    gcd_step = step(
        1,
        "Verificar que e1 y e2 sean coprimos",
        f"El ataque requiere gcd(e1, e2) = 1. Con Euclides extendido: gcd({e1},{e2}) = {g}, y se "
        f"encuentran a={a}, b={b} tales que a·e1 + b·e2 = {g}.",
        formula=f"{a}·{e1} + {b}·{e2} = {g}",
        columns=["q", "r0", "r1", "r", "s0", "s1", "s", "t0", "t1", "t"],
        rows=euclid_rows,
        ok=(g == 1),
    )

    if g != 1:
        msg = f"gcd(e1,e2) = {g} != 1 -- el ataque de módulo común no aplica con estos exponentes."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="common_modulus",
            input_summary={"n": n, "e1": e1, "c1": c1, "e2": e2, "c2": c2}, output=None,
            output_label="Resultado", steps=[gcd_step], error=msg,
        )

    part1, rows1 = _mod_pow_signed(c1, a, n)
    part2, rows2 = _mod_pow_signed(c2, b, n)
    m = (part1 * part2) % n

    part1_step = step(
        2,
        "Calcular c1^a mod n",
        f"c1^a mod n = {c1}^{a} mod {n} = {part1}" + (" (a es negativo: se usa el inverso modular de c1 como base)" if a < 0 else ""),
        columns=["Bit del exponente", "resultado^2 mod n", "cuadrado", "multiplicar?", "nuevo resultado"],
        rows=rows1,
    )
    part2_step = step(
        3,
        "Calcular c2^b mod n",
        f"c2^b mod n = {c2}^{b} mod {n} = {part2}" + (" (b es negativo: se usa el inverso modular de c2 como base)" if b < 0 else ""),
        columns=["Bit del exponente", "resultado^2 mod n", "cuadrado", "multiplicar?", "nuevo resultado"],
        rows=rows2,
    )
    combine_step = step(
        4,
        "Combinar: m = c1^a · c2^b mod n",
        f"m = {part1} × {part2} mod {n} = {m}. "
        "Se recuperó el mensaje original sin conocer ninguna llave privada -- solo con dos cifrados "
        "del MISMO mensaje bajo el MISMO n con exponentes distintos y coprimos.",
        extra={"m": m},
    )

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="common_modulus",
        input_summary={"n": n, "e1": e1, "c1": c1, "e2": e2, "c2": c2}, output=str(m),
        output_label="Mensaje recuperado", steps=[gcd_step, part1_step, part2_step, combine_step],
    )


def _continued_fraction(num: int, den: int) -> list[int]:
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


def _convergents(cf: list[int]) -> list[tuple[int, int]]:
    convs = []
    h_prev2, h_prev1 = 0, 1
    k_prev2, k_prev1 = 1, 0
    for a in cf:
        h = a * h_prev1 + h_prev2
        k = a * k_prev1 + k_prev2
        convs.append((h, k))
        h_prev2, h_prev1 = h_prev1, h
        k_prev2, k_prev1 = k_prev1, k
    return convs


def _is_perfect_square(x: int) -> tuple[bool, int]:
    if x < 0:
        return False, 0
    r = math.isqrt(x)
    return r * r == x, r


def wiener_attack(e: int, n: int) -> AlgorithmRunResult:
    cf = _continued_fraction(e, n)
    convs = _convergents(cf)

    rows = []
    found_d = None
    found_pq = None
    for k, d in convs:
        if k == 0 or d == 0:
            rows.append([k, d, "-", "k=0, se descarta"])
            continue
        if (e * d - 1) % k != 0:
            rows.append([k, d, "-", "(e·d - 1) no es divisible entre k"])
            continue
        phi_candidate = (e * d - 1) // k
        s = n - phi_candidate + 1  # p + q
        disc = s * s - 4 * n
        is_sq, root = _is_perfect_square(disc)
        if not is_sq:
            rows.append([k, d, phi_candidate, "p+q, p·q no dan raíces enteras"])
            continue
        p_cand = (s + root) // 2
        q_cand = (s - root) // 2
        if p_cand * q_cand == n and p_cand > 1 and q_cand > 1:
            rows.append([k, d, phi_candidate, f"¡VÁLIDO! p={p_cand}, q={q_cand}"])
            found_d = d
            found_pq = (p_cand, q_cand)
            break
        rows.append([k, d, phi_candidate, "p·q no coincide con n"])

    steps = [
        step(
            1,
            "Expandir e/n en fracción continua",
            f"e/n = {e}/{n} se expande como fracción continua: {cf}. Cada convergente k/d de esa "
            "expansión es un candidato a (k, d) del par (llave pública, llave privada).",
            extra={"cf": cf},
        ),
        step(
            2,
            "Probar cada convergente como candidato a d",
            "Para cada candidato d, se verifica si produce un φ(n) entero consistente con una "
            "factorización válida de n (resolviendo p+q y p·q como raíces de una ecuación cuadrática).",
            columns=["k", "d (candidato)", "φ(n) candidato", "Resultado"],
            rows=rows,
            ok=found_d is not None,
        ),
    ]

    if found_d is None:
        msg = "Ningún convergente produjo una factorización válida -- d probablemente no es lo bastante pequeño para que el ataque de Wiener funcione (condición: d < (1/3)·n^(1/4))."
        steps.append(step(3, "Resultado", msg, ok=False))
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="wiener",
            input_summary={"e": e, "n": n}, output=None, output_label="d recuperado",
            steps=steps, error=msg,
        )

    p, q = found_pq
    steps.append(
        step(
            3,
            "Llave privada recuperada",
            f"d={found_d}, y de paso se recuperó la factorización completa: p={p}, q={q}. Todo esto "
            "sin ningún acceso a la llave privada -- solo con la llave pública (e, n) y saber que d era "
            "pequeño.",
        )
    )

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="wiener",
        input_summary={"e": e, "n": n}, output=f"d={found_d} (p={p}, q={q})",
        output_label="Llave privada recuperada", steps=steps,
    )
