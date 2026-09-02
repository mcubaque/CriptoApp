"""RSA with small primes so every step (n, phi(n), e, d via extended Euclid,
modular exponentiation via square-and-multiply) is verifiable by hand.

En el mundo real: RSA real usa primos de 1024+ bits; aqui usamos primos
pequenos (p, q < 10000) para que la aritmetica se pueda verificar a mano.
"""
from __future__ import annotations

from app.core.numeric_utils import extended_gcd_steps, gcd, is_prime, mod_pow_steps
from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "asymmetric"
ALGORITHM = "rsa"


def keygen(p: int, q: int, e: int) -> AlgorithmRunResult:
    if not is_prime(p) or not is_prime(q):
        msg = f"p={p} y q={q} deben ser numeros primos."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="keygen",
            input_summary={"p": p, "q": q, "e": e}, output=None, output_label="Llaves",
            steps=[step(1, "Validar p y q", msg, ok=False)], error=msg,
        )
    if p == q:
        msg = "p y q deben ser primos distintos."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="keygen",
            input_summary={"p": p, "q": q, "e": e}, output=None, output_label="Llaves",
            steps=[step(1, "Validar p y q", msg, ok=False)], error=msg,
        )

    n = p * q
    phi = (p - 1) * (q - 1)

    steps = [
        step(1, "Verificar que p y q son primos", f"p={p} es primo, q={q} es primo."),
        step(2, "Calcular n = p . q", f"n = {p} . {q} = {n}", formula=f"n = p.q = {n}"),
        step(3, "Calcular phi(n) = (p-1)(q-1)", f"phi(n) = ({p}-1)({q}-1) = {phi}", formula=f"phi(n) = {phi}"),
    ]

    if gcd(e, phi) != 1:
        msg = f"e={e} no es valido: gcd(e, phi(n)) = gcd({e},{phi}) = {gcd(e, phi)} != 1."
        steps.append(step(4, "Verificar e", msg, ok=False))
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="keygen",
            input_summary={"p": p, "q": q, "e": e}, output=None, output_label="Llaves",
            steps=steps, error=msg,
        )

    steps.append(step(4, "Verificar que e es valido", f"gcd(e, phi(n)) = gcd({e},{phi}) = 1, asi que e es un exponente publico valido."))

    g, x, _y, euclid_rows = extended_gcd_steps(e, phi)
    d = x % phi

    steps.append(
        step(
            5,
            "Calcular d = e^-1 mod phi(n) con Euclides extendido",
            f"Se busca d tal que e.d = 1 mod phi(n). Con el algoritmo de Euclides extendido, d = {d}.",
            formula=f"d = {d}",
            columns=["q", "r0", "r1", "r", "s0", "s1", "s", "t0", "t1", "t"],
            rows=euclid_rows,
        )
    )

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="keygen",
        input_summary={"p": p, "q": q, "e": e},
        output=f"n={n}, e={e}, d={d}",
        output_label="Llave publica (n,e) y privada (n,d)",
        steps=steps,
        error=None,
    )


def encrypt(m: int, e: int, n: int) -> AlgorithmRunResult:
    if m < 0 or m >= n:
        msg = f"El mensaje numerico m={m} debe cumplir 0 <= m < n (n={n})."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="encrypt",
            input_summary={"m": m, "e": e, "n": n}, output=None, output_label="Texto cifrado",
            steps=[step(1, "Validar el mensaje", msg, ok=False)], error=msg,
        )

    c, rows = mod_pow_steps(m, e, n)
    steps = [
        step(
            1,
            "Cifrar: c = m^e mod n",
            f"Se calcula {m}^{e} mod {n} usando exponenciacion rapida (cuadrado y multiplica), "
            "bit a bit del exponente en binario.",
            formula=f"c = {m}^{e} mod {n} = {c}",
            columns=["Bit de e", "resultado^2 mod n", "cuadrado", "multiplicar por m?", "nuevo resultado"],
            rows=rows,
        )
    ]
    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="encrypt",
        input_summary={"m": m, "e": e, "n": n}, output=str(c),
        output_label="Texto cifrado (numero)", steps=steps,
    )


def decrypt(c: int, d: int, n: int) -> AlgorithmRunResult:
    if c < 0 or c >= n:
        msg = f"El criptograma numerico c={c} debe cumplir 0 <= c < n (n={n})."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="decrypt",
            input_summary={"c": c, "d": d, "n": n}, output=None, output_label="Texto plano",
            steps=[step(1, "Validar el criptograma", msg, ok=False)], error=msg,
        )

    m, rows = mod_pow_steps(c, d, n)
    steps = [
        step(
            1,
            "Descifrar: m = c^d mod n",
            f"Se calcula {c}^{d} mod {n} usando exponenciacion rapida (cuadrado y multiplica).",
            formula=f"m = {c}^{d} mod {n} = {m}",
            columns=["Bit de d", "resultado^2 mod n", "cuadrado", "multiplicar por c?", "nuevo resultado"],
            rows=rows,
        )
    ]
    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="decrypt",
        input_summary={"c": c, "d": d, "n": n}, output=str(m),
        output_label="Texto plano (numero)", steps=steps,
    )
