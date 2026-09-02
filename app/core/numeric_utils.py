"""Hand-written number theory helpers. Deliberately not delegated to a library:
the whole point of this app is that every intermediate step (gcd, modular
inverse, modular exponentiation) is something we computed and can display,
not a library black box.
"""
from __future__ import annotations

import random


def gcd(a: int, b: int) -> int:
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd_steps(a: int, b: int) -> tuple[int, int, int, list[list]]:
    """Extended Euclidean algorithm, iterative, returning (gcd, x, y, rows)
    such that a*x + b*y = gcd, plus a table of rows for display:
    [q, r0, r1, r, s0, s1, s, t0, t1, t]
    """
    rows: list[list] = []
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    rows.append(["-", old_r, r, "-", old_s, s, "-", old_t, t, "-"])

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
        rows.append([q, "-", "-", r, "-", "-", s, "-", "-", t])

    return old_r, old_s, old_t, rows


def modinv(a: int, n: int) -> int | None:
    g, x, _y, _rows = extended_gcd_steps(a, n)
    if g != 1:
        return None
    return x % n


def mod_pow_steps(base: int, exponent: int, modulus: int) -> tuple[int, list[list]]:
    """Square-and-multiply modular exponentiation, returning (result, rows)
    where each row documents one bit of the exponent:
    [bit, "result^2 mod n", squared_value, "* base?", value_after_multiply]
    """
    if modulus == 1:
        return 0, []

    rows: list[list] = []
    result = 1
    base = base % modulus
    bits = bin(exponent)[2:]

    for bit in bits:
        squared = (result * result) % modulus
        if bit == "1":
            after = (squared * base) % modulus
            rows.append([bit, f"{result}^2 mod {modulus} = {squared}", squared, "si", after])
        else:
            after = squared
            rows.append([bit, f"{result}^2 mod {modulus} = {squared}", squared, "no", after])
        result = after

    return result, rows


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def random_small_prime(low: int = 11, high: int = 200) -> int:
    candidates = [n for n in range(low, high + 1) if is_prime(n)]
    return random.choice(candidates)


def small_primes_up_to(limit: int) -> list[int]:
    return [n for n in range(2, limit + 1) if is_prime(n)]
