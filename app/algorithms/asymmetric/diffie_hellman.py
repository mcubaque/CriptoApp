"""Diffie-Hellman key exchange with a small prime modulus so the two-party
simulation is verifiable by hand.

En el mundo real: DH real usa primos de 2048+ bits; aqui usamos numeros
pequenos para poder verificar cada exponenciacion a mano.
"""
from __future__ import annotations

from app.core.numeric_utils import is_prime, mod_pow_steps
from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "asymmetric"
ALGORITHM = "diffie_hellman"


def exchange(p: int, g: int, a: int, b: int) -> AlgorithmRunResult:
    if not is_prime(p):
        msg = f"p={p} debe ser un numero primo."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="exchange",
            input_summary={"p": p, "g": g, "a": a, "b": b}, output=None, output_label="Secreto compartido",
            steps=[step(1, "Validar p", msg, ok=False)], error=msg,
        )
    if not (1 < g < p):
        msg = f"g={g} debe cumplir 1 < g < p (p={p})."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="exchange",
            input_summary={"p": p, "g": g, "a": a, "b": b}, output=None, output_label="Secreto compartido",
            steps=[step(1, "Validar g", msg, ok=False)], error=msg,
        )

    public_a, rows_a = mod_pow_steps(g, a, p)
    public_b, rows_b = mod_pow_steps(g, b, p)

    steps = [
        step(1, "Parametros publicos", f"Se acuerda un primo p={p} y un generador g={g} (ambos publicos)."),
        step(
            2,
            "A calcula su valor publico",
            f"A elige en secreto a={a} y calcula A = g^a mod p = {g}^{a} mod {p} = {public_a}.",
            formula=f"A = {public_a}",
            columns=["Bit de a", "resultado^2 mod p", "cuadrado", "multiplicar por g?", "nuevo resultado"],
            rows=rows_a,
        ),
        step(
            3,
            "B calcula su valor publico",
            f"B elige en secreto b={b} y calcula B = g^b mod p = {g}^{b} mod {p} = {public_b}.",
            formula=f"B = {public_b}",
            columns=["Bit de b", "resultado^2 mod p", "cuadrado", "multiplicar por g?", "nuevo resultado"],
            rows=rows_b,
        ),
    ]

    secret_a, rows_secret_a = mod_pow_steps(public_b, a, p)
    secret_b, rows_secret_b = mod_pow_steps(public_a, b, p)

    steps.append(
        step(
            4,
            "A calcula el secreto compartido",
            f"A recibe B={public_b} y calcula B^a mod p = {public_b}^{a} mod {p} = {secret_a}.",
            formula=f"secreto_A = {secret_a}",
            columns=["Bit de a", "resultado^2 mod p", "cuadrado", "multiplicar por B?", "nuevo resultado"],
            rows=rows_secret_a,
        )
    )
    steps.append(
        step(
            5,
            "B calcula el secreto compartido",
            f"B recibe A={public_a} y calcula A^b mod p = {public_a}^{b} mod {p} = {secret_b}.",
            formula=f"secreto_B = {secret_b}",
            columns=["Bit de b", "resultado^2 mod p", "cuadrado", "multiplicar por A?", "nuevo resultado"],
            rows=rows_secret_b,
        )
    )

    both_match = secret_a == secret_b
    steps.append(
        step(
            6,
            "Verificar que ambos secretos coinciden",
            f"secreto_A = {secret_a}, secreto_B = {secret_b}. "
            + ("Ambos coinciden: ese es el secreto compartido." if both_match else "No coinciden (esto no deberia pasar; revisa los datos)."),
            ok=both_match,
        )
    )

    return AlgorithmRunResult(
        ok=both_match,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="exchange",
        input_summary={"p": p, "g": g, "a": a, "b": b},
        output=str(secret_a) if both_match else None,
        output_label="Secreto compartido",
        steps=steps,
        error=None if both_match else "Los secretos calculados no coinciden.",
    )
