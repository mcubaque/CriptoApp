"""Password cracking demos: dictionary attack, bounded brute force, and salting.
Reuses app.algorithms.authentication.hash_demo's hashing (same hashlib wrapper).
"""
from __future__ import annotations

import itertools

from app.algorithms.authentication.hash_demo import SUPPORTED, _digest
from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "authentication"
ALGORITHM = "password_cracking"

COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345", "qwerty", "abc123", "111111",
    "letmein", "admin", "welcome", "monkey", "login", "princess", "solo",
    "iloveyou", "starwars", "dragon", "master", "hello", "freedom", "whatever",
    "trustno1", "football", "sunshine", "12345678", "1234567", "1234567890",
    "qwerty123", "000000", "654321",
]

MAX_BRUTEFORCE_ATTEMPTS = 200_000


def crack_dictionary(target_hash: str, algorithm: str = "sha256") -> AlgorithmRunResult:
    target_hash = target_hash.strip().lower()
    rows = []
    found = None
    for word in COMMON_PASSWORDS:
        h = _digest(word, algorithm)
        match = h == target_hash
        rows.append([word, h, "SÍ" if match else "no"])
        if match:
            found = word
            break

    steps = [
        step(
            1,
            "Probar contraseñas comunes contra el hash objetivo",
            f"Se hashea cada palabra de una lista de {len(COMMON_PASSWORDS)} contraseñas comunes con "
            f"{algorithm.upper()} y se compara contra el hash objetivo. Esto es exactamente lo que hace "
            "un atacante real como primer paso, antes de intentar fuerza bruta: la mayoría de la gente "
            "usa contraseñas muy predecibles.",
            columns=["Intento", "Hash calculado", "¿Coincide?"],
            rows=rows,
            ok=found is not None,
        )
    ]

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="dictionary",
        input_summary={"target_hash": target_hash, "algorithm": algorithm},
        output=found if found else None,
        output_label="Contraseña encontrada" if found else "No se encontró en el diccionario",
        steps=steps,
    )


def crack_bruteforce(
    target_hash: str, charset: str = "abcdefghijklmnopqrstuvwxyz", max_length: int = 3,
    algorithm: str = "sha256",
) -> AlgorithmRunResult:
    target_hash = target_hash.strip().lower()
    charset = charset or "abcdefghijklmnopqrstuvwxyz"
    max_length = max(1, min(max_length, 5))

    space_size = sum(len(charset) ** l for l in range(1, max_length + 1))
    if space_size > MAX_BRUTEFORCE_ATTEMPTS:
        msg = (
            f"El espacio de búsqueda ({space_size:,} combinaciones) es demasiado grande para esta demo "
            f"(tope: {MAX_BRUTEFORCE_ATTEMPTS:,}). Reduce el alfabeto o la longitud máxima."
        )
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="bruteforce",
            input_summary={"target_hash": target_hash, "charset": charset, "max_length": max_length},
            output=None, output_label="Resultado",
            steps=[step(1, "Validar el tamaño del espacio de búsqueda", msg, ok=False)], error=msg,
        )

    found = None
    attempts = 0
    sample_rows = []
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1
            h = _digest(candidate, algorithm)
            if len(sample_rows) < 15:
                sample_rows.append([candidate, h])
            if h == target_hash:
                found = candidate
                break
        if found:
            break

    steps = [
        step(
            1,
            "Fuerza bruta acotada",
            f"Se prueban todas las combinaciones de {len(charset)} caracteres posibles, de longitud 1 "
            f"a {max_length} ({space_size:,} combinaciones en total). Se muestran solo los primeros "
            f"intentos como ejemplo.",
            columns=["Intento (muestra)", "Hash calculado"],
            rows=sample_rows,
        ),
        step(
            2,
            "Resultado",
            (
                f"Contraseña encontrada tras {attempts:,} intentos: '{found}'."
                if found
                else f"No se encontró en las {attempts:,} combinaciones probadas."
            ),
            extra={"attempts": attempts, "space_size": space_size},
            ok=found is not None,
        ),
    ]

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="bruteforce",
        input_summary={"target_hash": target_hash, "charset": charset, "max_length": max_length},
        output=found,
        output_label="Contraseña encontrada" if found else "No encontrada",
        steps=steps,
    )


def salt_demo(password: str, salt_a: str, salt_b: str, algorithm: str = "sha256") -> AlgorithmRunResult:
    hash_plain = _digest(password, algorithm)
    hash_a = _digest(password + salt_a, algorithm)
    hash_b = _digest(password + salt_b, algorithm)

    steps = [
        step(1, "Hash sin sal", f"{algorithm.upper()}('{password}') = {hash_plain}",
             extra={"note": "Dos usuarios con la misma contraseña tendrían el MISMO hash — visible para cualquiera con acceso a la base de datos."}),
        step(2, "Hash con sal A", f"{algorithm.upper()}('{password}' + '{salt_a}') = {hash_a}"),
        step(3, "Hash con sal B", f"{algorithm.upper()}('{password}' + '{salt_b}') = {hash_b}"),
        step(
            4,
            "Comparación",
            "La MISMA contraseña con DOS sales distintas produce hashes completamente distintos "
            f"({'diferentes' if hash_a != hash_b else 'iguales -- esto no debería pasar'}). "
            "Por eso la sal derrota las 'rainbow tables' (tablas precalculadas de hash→contraseña): "
            "un atacante tendría que precalcular una tabla distinta para cada sal posible.",
            ok=hash_a != hash_b,
        ),
    ]

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="salt",
        input_summary={"text": password, "salt_a": salt_a, "salt_b": salt_b, "algorithm": algorithm},
        output=f"{hash_a[:16]}... vs {hash_b[:16]}...",
        output_label="Hashes con sal (comparación)",
        steps=steps,
    )
