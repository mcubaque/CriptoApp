"""Hash functions as a black box, deliberately: SHA-256/SHA-1/MD5 wrap Python's
stdlib hashlib rather than being reimplemented by hand. Real SHA-256 has 64 rounds
and a nontrivial message schedule -- reimplementing it step-by-step would be a lot
of code for little pedagogical payoff compared to S-DES/S-AES (2 rounds, meant to
be traced in full). Here the teaching goal is different: showing WHAT a hash does
(fixed-size output, avalanche effect, keyed variants) rather than HOW it computes
internally.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib

from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "authentication"
ALGORITHM = "hash"

SUPPORTED = {"sha256": hashlib.sha256, "sha1": hashlib.sha1, "md5": hashlib.md5}


def _digest(text: str, algorithm: str) -> str:
    fn = SUPPORTED[algorithm]
    return fn(text.encode("utf-8")).hexdigest()


def compute_hash(text: str, algorithm: str = "sha256") -> AlgorithmRunResult:
    if algorithm not in SUPPORTED:
        msg = f"Algoritmo no soportado: {algorithm}. Usa sha256, sha1 o md5."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="hash",
            input_summary={"text": text, "algorithm": algorithm}, output=None,
            output_label="Hash", steps=[step(1, "Validar algoritmo", msg, ok=False)], error=msg,
        )

    digest = _digest(text, algorithm)
    steps = [
        step(
            1,
            "Convertir el texto a bytes (UTF-8)",
            f"'{text}' se codifica como una secuencia de bytes antes de hashear.",
            extra={"bytes_len": len(text.encode("utf-8"))},
        ),
        step(
            2,
            f"Calcular {algorithm.upper()}",
            f"Se pasa la secuencia de bytes por la función hash {algorithm.upper()} (implementación "
            "estándar de Python, no reimplementada a mano — ver la nota más abajo).",
            formula=f"{algorithm.upper()}('{text}') = {digest}",
            extra={"digest_bits": len(digest) * 4},
        ),
    ]

    note = ""
    if algorithm in ("md5", "sha1"):
        note = " (MD5 y SHA-1 ya NO se recomiendan: se conocen colisiones prácticas para ambos.)"

    steps.append(
        step(
            3,
            "Propiedades del resultado",
            f"El hash siempre tiene el mismo tamaño ({len(digest) * 4} bits = {len(digest)} caracteres "
            f"hexadecimales) sin importar qué tan largo sea el texto de entrada, y es determinista: "
            f"el mismo texto siempre produce el mismo hash.{note}",
        )
    )

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="hash",
        input_summary={"text": text, "algorithm": algorithm}, output=digest,
        output_label=f"{algorithm.upper()} (hex)", steps=steps,
    )


def avalanche_demo(text_a: str, text_b: str, algorithm: str = "sha256") -> AlgorithmRunResult:
    digest_a = _digest(text_a, algorithm)
    digest_b = _digest(text_b, algorithm)

    bits_a = bin(int(digest_a, 16))[2:].zfill(len(digest_a) * 4)
    bits_b = bin(int(digest_b, 16))[2:].zfill(len(digest_b) * 4)
    diff_bits = sum(1 for x, y in zip(bits_a, bits_b) if x != y)
    total_bits = len(bits_a)
    pct = round(diff_bits / total_bits * 100, 1)

    steps = [
        step(1, "Hashear el primer texto", f"{algorithm.upper()}('{text_a}') = {digest_a}"),
        step(2, "Hashear el segundo texto", f"{algorithm.upper()}('{text_b}') = {digest_b}"),
        step(
            3,
            "Contar bits distintos (distancia de Hamming)",
            f"De los {total_bits} bits del hash, {diff_bits} son distintos entre los dos resultados "
            f"({pct}%). Este es el 'efecto avalancha': un cambio mínimo en la entrada (aunque sea 1 "
            "carácter) produce un hash completamente distinto, sin ningún parecido visible con el "
            "original -- así es como debe comportarse una buena función hash criptográfica.",
            extra={"diff_bits": diff_bits, "total_bits": total_bits, "pct": pct},
        ),
    ]

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="avalanche",
        input_summary={"text_a": text_a, "text_b": text_b, "algorithm": algorithm},
        output=f"{diff_bits}/{total_bits} bits distintos ({pct}%)",
        output_label="Diferencia entre hashes", steps=steps,
    )


def hmac_demo(key: str, message: str, algorithm: str = "sha256") -> AlgorithmRunResult:
    if algorithm not in SUPPORTED:
        algorithm = "sha256"
    digestmod = SUPPORTED[algorithm]
    tag = hmac_lib.new(key.encode("utf-8"), message.encode("utf-8"), digestmod).hexdigest()

    steps = [
        step(
            1,
            "HMAC combina una llave secreta con el mensaje",
            "A diferencia de un hash simple (que cualquiera puede calcular), HMAC mezcla la llave "
            "secreta con el mensaje de una forma específica antes y después de hashear, así que solo "
            "quien conoce la llave puede generar o verificar el código.",
        ),
        step(
            2,
            f"Calcular HMAC-{algorithm.upper()}(llave, mensaje)",
            f"HMAC-{algorithm.upper()}('{key}', '{message}') = {tag}",
            formula=f"HMAC(K, m) = {tag}",
        ),
        step(
            3,
            "Para qué sirve",
            "HMAC da integridad Y autenticidad: si alguien altera el mensaje en tránsito, o no conoce "
            "la llave, el HMAC recalculado no va a coincidir. Un hash simple solo da integridad "
            "(cualquiera puede recalcularlo), no prueba quién lo generó.",
        ),
    ]

    return AlgorithmRunResult(
        ok=True, family=FAMILY, algorithm=ALGORITHM, operation="hmac",
        input_summary={"key": key, "text": message, "algorithm": algorithm},
        output=tag, output_label=f"HMAC-{algorithm.upper()} (hex)", steps=steps,
    )
