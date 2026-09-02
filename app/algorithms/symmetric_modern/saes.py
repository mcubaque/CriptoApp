"""Simplified AES (S-AES), the standard teaching variant (Musa/Schaefer/Wong):
16-bit key, 16-bit block (4 nibbles), GF(2^4) arithmetic with reduction
polynomial x^4+x+1 (0x13), 2 rounds. Every table and the worked example below
(K=0100101011110101, P=1101011100101000 -> C=0010010011101100) were
cross-checked step-by-step, including every GF(2^4) multiplication, against
Steven Gordon's "Simplified AES Example" (SIIT CSS 322, 3 Dec 2009).

En el mundo real: AES real usa un estado de 16 bytes, claves de 128+ bits,
10-14 rondas y aritmetica en GF(2^8); S-AES usa 4 nibbles, una clave de 16
bits y 2 rondas para que cada multiplicacion se pueda verificar a mano.
"""
from __future__ import annotations

from app.core.step_trace import AlgorithmRunResult, Step, StepTable, step

FAMILY = "symmetric_modern"
ALGORITHM = "saes"

# row = first 2 bits of the nibble, col = last 2 bits
S_BOX = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7],
]

RCON1 = "10000000"
RCON2 = "00110000"
GF_POLY = 0x13  # x^4 + x + 1


def _build_inverse_sbox() -> dict[int, int]:
    inv = {}
    for row in range(4):
        for col in range(4):
            nibble_in = (row << 2) | col
            nibble_out = S_BOX[row][col]
            inv[nibble_out] = nibble_in
    return inv


INV_S_BOX_MAP = _build_inverse_sbox()


def _nib_to_int(nibble: str) -> int:
    return int(nibble, 2)


def _int_to_nib(n: int) -> str:
    return format(n & 0xF, "04b")


def _sub_nibble_str(nibble: str, inverse: bool = False) -> str:
    n = _nib_to_int(nibble)
    if inverse:
        return _int_to_nib(INV_S_BOX_MAP[n])
    row, col = n >> 2, n & 0x3
    return _int_to_nib(S_BOX[row][col])


def _sub_nibbles(nibbles: list[str], inverse: bool = False) -> list[str]:
    return [_sub_nibble_str(n, inverse) for n in nibbles]


def _rot_nib(byte8: str) -> str:
    return byte8[4:] + byte8[:4]


def _xor(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def _gf_mult(a: int, b: int) -> int:
    result = 0
    a &= 0xF
    b &= 0xF
    for _ in range(4):
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x10:
            a ^= GF_POLY
    return result & 0xF


def _gf_mult_nib(a: str, b_const: int) -> str:
    return _int_to_nib(_gf_mult(_nib_to_int(a), b_const))


def _shift_row(nibbles: list[str]) -> list[str]:
    n0, n1, n2, n3 = nibbles
    return [n0, n3, n2, n1]


def _mix_columns(nibbles: list[str]) -> list[str]:
    a, b, c, d = nibbles
    s00 = _xor(a, _gf_mult_nib(c, 4))
    s10 = _xor(_gf_mult_nib(a, 4), c)
    s01 = _xor(b, _gf_mult_nib(d, 4))
    s11 = _xor(_gf_mult_nib(b, 4), d)
    return [s00, s10, s01, s11]


def _inv_mix_columns(nibbles: list[str]) -> list[str]:
    # True positional inverse of _mix_columns: mix_columns([x0,x1,x2,x3]) computes
    # y0=x0^4*x2, y1=4*x0^x2, y2=x1^4*x3, y3=4*x1^x3. Solving that 2x2 GF(2^4)
    # system back (Md=[[9,2],[2,9]] is the inverse of Me=[[1,4],[4,1]]) gives
    # x0=9*y0^2*y1, x2=2*y0^9*y1, x1=9*y2^2*y3, x3=2*y2^9*y3.
    y0, y1, y2, y3 = nibbles
    x0 = _xor(_gf_mult_nib(y0, 9), _gf_mult_nib(y1, 2))
    x2 = _xor(_gf_mult_nib(y0, 2), _gf_mult_nib(y1, 9))
    x1 = _xor(_gf_mult_nib(y2, 9), _gf_mult_nib(y3, 2))
    x3 = _xor(_gf_mult_nib(y2, 2), _gf_mult_nib(y3, 9))
    return [x0, x1, x2, x3]


def _validate_bits(value: str, length: int, label: str) -> str | None:
    value = value.strip()
    if len(value) != length or any(c not in "01" for c in value):
        return f"{label} debe ser una cadena de exactamente {length} bits (solo 0s y 1s)."
    return None


def _nibbles_of(bits16: str) -> list[str]:
    return [bits16[0:4], bits16[4:8], bits16[8:12], bits16[12:16]]


def generate_keys(key16: str) -> tuple[str, str, str, Step]:
    w0, w1 = key16[:8], key16[8:]

    g1 = _xor(_xor(w0, RCON1), "".join(_sub_nibble_str(n) for n in [_rot_nib(w1)[:4], _rot_nib(w1)[4:]]))
    w2 = g1
    w3 = _xor(w2, w1)

    g2 = _xor(_xor(w2, RCON2), "".join(_sub_nibble_str(n) for n in [_rot_nib(w3)[:4], _rot_nib(w3)[4:]]))
    w4 = g2
    w5 = _xor(w4, w3)

    key0 = w0 + w1
    key1 = w2 + w3
    key2 = w4 + w5

    table = StepTable(
        columns=["Palabra", "Valor (8 bits)", "Como se obtuvo"],
        rows=[
            ["w0", w0, "primera mitad de la llave K"],
            ["w1", w1, "segunda mitad de la llave K"],
            ["w2", w2, "w0 XOR RCON1 XOR SubNib(RotNib(w1))"],
            ["w3", w3, "w2 XOR w1"],
            ["w4", w4, "w2 XOR RCON2 XOR SubNib(RotNib(w3))"],
            ["w5", w5, "w4 XOR w3"],
        ],
    )

    keygen_step = Step(
        index=1,
        title="Generar las subclaves Key0, Key1, Key2",
        explanation=(
            "La llave de 16 bits se parte en dos palabras w0,w1. Key0 = w0||w1 es la llave original. "
            "w2 combina w0, una constante de ronda (RCON1) y el resultado de rotar y sustituir los "
            "nibbles de w1; w3 = w2 XOR w1. w4 y w5 se generan igual mirando w2,w3 y RCON2."
        ),
        table=table,
        extra={"key0": key0, "key1": key1, "key2": key2},
    )
    return key0, key1, key2, keygen_step


def _nibble_step(index: int, title: str, explanation: str, nibbles: list[str], formula: str | None = None) -> Step:
    return step(
        index,
        title,
        explanation,
        formula=formula,
        columns=["n0", "n1", "n2", "n3", "(16 bits)"],
        rows=[nibbles + ["".join(nibbles)]],
    )


def _run(input_bits: str, key16: str, operation: str, raw_input: str) -> AlgorithmRunResult:
    err = _validate_bits(key16, 16, "La llave") or _validate_bits(input_bits, 16, "El bloque")
    if err:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation=operation,
            input_summary={"text": raw_input, "key": key16}, output=None,
            output_label="Resultado",
            steps=[step(1, "Validar entradas", err, ok=False)], error=err,
        )

    key0, key1, key2, keygen_step = generate_keys(key16)
    steps = [keygen_step]
    idx = 2

    if operation == "encrypt":
        state = _xor(input_bits, key0)
        steps.append(step(idx, "AddRoundKey 0", f"XOR del bloque con Key0: {input_bits} XOR {key0} = {state}."))
        idx += 1
        nibbles = _nibbles_of(state)

        nibbles = _sub_nibbles(nibbles)
        steps.append(_nibble_step(idx, "Ronda 1 - SubNibbles", "Cada nibble pasa por la S-box de cifrado.", nibbles))
        idx += 1

        nibbles = _shift_row(nibbles)
        steps.append(_nibble_step(idx, "Ronda 1 - ShiftRow", "Se intercambian el 2do y 4to nibble.", nibbles))
        idx += 1

        nibbles = _mix_columns(nibbles)
        steps.append(_nibble_step(idx, "Ronda 1 - MixColumns", "Multiplicacion matricial en GF(2^4) con la matriz [[1,4],[4,1]].", nibbles))
        idx += 1

        state = "".join(nibbles)
        state = _xor(state, key1)
        nibbles = _nibbles_of(state)
        steps.append(step(idx, "AddRoundKey 1", f"XOR con Key1: {key1}. Resultado: {state}.", columns=["n0", "n1", "n2", "n3", "(16 bits)"], rows=[nibbles + [state]]))
        idx += 1

        nibbles = _sub_nibbles(nibbles)
        steps.append(_nibble_step(idx, "Ronda final - SubNibbles", "Cada nibble pasa por la S-box de cifrado.", nibbles))
        idx += 1

        nibbles = _shift_row(nibbles)
        steps.append(_nibble_step(idx, "Ronda final - ShiftRow", "Se intercambian el 2do y 4to nibble.", nibbles))
        idx += 1

        state = "".join(nibbles)
        final = _xor(state, key2)
        steps.append(step(idx, "AddRoundKey 2 (final)", f"XOR con Key2: {key2}. Ciphertext: {final}."))
        output_label = "Texto cifrado (16 bits)"

    else:
        state = _xor(input_bits, key2)
        steps.append(step(idx, "AddRoundKey 2 (inversa)", f"XOR del bloque cifrado con Key2: {input_bits} XOR {key2} = {state}."))
        idx += 1
        nibbles = _nibbles_of(state)

        nibbles = _shift_row(nibbles)
        steps.append(_nibble_step(idx, "InvShiftRow", "Se intercambian el 2do y 4to nibble (es su propia inversa).", nibbles))
        idx += 1

        nibbles = _sub_nibbles(nibbles, inverse=True)
        steps.append(_nibble_step(idx, "InvSubNibbles", "Cada nibble pasa por la S-box inversa (de descifrado).", nibbles))
        idx += 1

        state = "".join(nibbles)
        state = _xor(state, key1)
        nibbles = _nibbles_of(state)
        steps.append(step(idx, "AddRoundKey 1", f"XOR con Key1: {key1}. Resultado: {state}.", columns=["n0", "n1", "n2", "n3", "(16 bits)"], rows=[nibbles + [state]]))
        idx += 1

        nibbles = _inv_mix_columns(nibbles)
        steps.append(_nibble_step(idx, "InvMixColumns", "Multiplicacion matricial en GF(2^4) con la matriz inversa [[9,2],[2,9]].", nibbles))
        idx += 1

        nibbles = _shift_row(nibbles)
        steps.append(_nibble_step(idx, "InvShiftRow", "Se intercambian el 2do y 4to nibble.", nibbles))
        idx += 1

        nibbles = _sub_nibbles(nibbles, inverse=True)
        steps.append(_nibble_step(idx, "InvSubNibbles", "Cada nibble pasa por la S-box inversa.", nibbles))
        idx += 1

        state = "".join(nibbles)
        final = _xor(state, key0)
        steps.append(step(idx, "AddRoundKey 0 (final)", f"XOR con Key0: {key0}. Texto plano: {final}."))
        output_label = "Texto plano (16 bits)"

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation=operation,
        input_summary={"text": raw_input, "key": key16},
        output=final,
        output_label=output_label,
        steps=steps,
    )


def encrypt(plaintext16: str, key16: str) -> AlgorithmRunResult:
    return _run(plaintext16.strip(), key16.strip(), "encrypt", plaintext16)


def decrypt(ciphertext16: str, key16: str) -> AlgorithmRunResult:
    return _run(ciphertext16.strip(), key16.strip(), "decrypt", ciphertext16)
