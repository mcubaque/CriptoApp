"""Simplified DES (S-DES), the standard teaching variant (Schaefer / Stallings):
10-bit key, 8-bit block, 2 Feistel rounds. Every table and the verification
example below (K=1100011110, P=00101000 -> C=10001010, K1=11101001,
K2=10100111) were cross-checked bit-by-bit against a fully worked reference
example (ISE334/SE425 Recitation 3, based on Stallings' S-DES description).

En el mundo real: AES usa claves de 128+ bits y 10-14 rondas; S-DES usa una
clave de 10 bits y 2 rondas para que cada paso se pueda verificar a mano.
"""
from __future__ import annotations

from app.core.step_trace import AlgorithmRunResult, Step, StepTable, step

FAMILY = "symmetric_modern"
ALGORITHM = "sdes"

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


def _permute(bits: str, table: list[int]) -> str:
    return "".join(bits[i - 1] for i in table)


def _rotate_left(bits: str, n: int) -> str:
    return bits[n:] + bits[:n]


def _xor(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def _sbox_value(bits4: str, sbox: list[list[int]]) -> str:
    row = int(bits4[0] + bits4[3], 2)
    col = int(bits4[1] + bits4[2], 2)
    return format(sbox[row][col], "02b")


def _validate_bits(value: str, length: int, label: str) -> str | None:
    value = value.strip()
    if len(value) != length or any(c not in "01" for c in value):
        return f"{label} debe ser una cadena de exactamente {length} bits (solo 0s y 1s)."
    return None


def generate_keys(key10: str) -> tuple[str, str, Step]:
    p10 = _permute(key10, P10)
    l0, r0 = p10[:5], p10[5:]
    l1, r1 = _rotate_left(l0, 1), _rotate_left(r0, 1)
    shift1 = l1 + r1
    k1 = _permute(shift1, P8)

    l2, r2 = _rotate_left(l1, 2), _rotate_left(r1, 2)
    shift2 = l2 + r2
    k2 = _permute(shift2, P8)

    table = StepTable(
        columns=["Etapa"] + [str(i) for i in range(1, 11)],
        rows=[
            ["K (llave original)"] + list(key10),
            ["P10(K)"] + list(p10),
            ["LS-1 (rota cada mitad 1 bit)"] + list(shift1),
            ["P8 -> K1"] + list(k1) + ["-", "-"],
            ["LS-2 (rota 2 bits mas desde LS-1)"] + list(shift2),
            ["P8 -> K2"] + list(k2) + ["-", "-"],
        ],
    )

    keygen_step = Step(
        index=1,
        title="Generar las subclaves K1 y K2",
        explanation=(
            "P10 reordena los 10 bits de la llave. Se parte en dos mitades de 5 bits, se rota "
            "cada mitad 1 posicion a la izquierda (LS-1) y se aplica P8 para obtener K1 (8 bits). "
            "Se vuelve a rotar 2 posiciones mas desde ahi (LS-2) y se aplica P8 de nuevo para K2."
        ),
        table=table,
    )
    return k1, k2, keygen_step


def _f_function(r4: str, k8: str, step_index: int, round_label: str) -> tuple[str, Step]:
    ep = _permute(r4, EP)
    xored = _xor(ep, k8)
    left4, right4 = xored[:4], xored[4:]
    s0_out = _sbox_value(left4, S0)
    s1_out = _sbox_value(right4, S1)
    sbox_out = s0_out + s1_out
    p4_out = _permute(sbox_out, P4)

    table = StepTable(
        columns=["Etapa", "1", "2", "3", "4", "5", "6", "7", "8"],
        rows=[
            ["R (4 bits)"] + list(r4) + ["-", "-", "-", "-"],
            ["E/P(R)"] + list(ep),
            [f"Subclave {round_label}"] + list(k8),
            ["E/P(R) XOR subclave"] + list(xored),
            ["S0(izq) | S1(der)"] + list(sbox_out) + ["-", "-", "-", "-"],
            ["P4(S-boxes) = F(R,K)"] + list(p4_out) + ["-", "-", "-", "-"],
        ],
    )

    f_step = Step(
        index=step_index,
        title=f"Calcular F(R, {round_label})",
        explanation=(
            "Expandimos R de 4 a 8 bits (E/P), lo combinamos con la subclave via XOR, partimos el "
            "resultado en dos mitades de 4 bits que pasan por las cajas S0 y S1 (cada una produce 2 "
            "bits), y aplicamos la permutacion P4 al resultado combinado."
        ),
        table=table,
    )
    return p4_out, f_step


def _run(plaintext_bits: str, key10: str, key_order: tuple[str, str], operation: str, raw_input: str) -> AlgorithmRunResult:
    err = _validate_bits(key10, 10, "La llave") or _validate_bits(plaintext_bits, 8, "El bloque")
    if err:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation=operation,
            input_summary={"text": raw_input, "key": key10}, output=None,
            output_label="Resultado",
            steps=[step(1, "Validar entradas", err, ok=False)], error=err,
        )

    k1, k2, keygen_step = generate_keys(key10)
    ka, kb = (k1, k2) if key_order == ("K1", "K2") else (k2, k1)
    label_a, label_b = key_order

    ip_out = _permute(plaintext_bits, IP)
    l0, r0 = ip_out[:4], ip_out[4:]

    ip_step = step(
        2,
        "Permutacion inicial (IP)",
        f"IP reordena los 8 bits del bloque de entrada: {plaintext_bits} -> {ip_out}. "
        f"Se parte en L0={l0} y R0={r0}.",
        extra={"ip_out": ip_out, "l0": l0, "r0": r0},
    )

    f1_out, f1_step = _f_function(r0, ka, 3, label_a)
    l1 = _xor(l0, f1_out)
    r1 = r0

    round1_step = step(
        4,
        f"Ronda 1: aplicar f{label_a}",
        f"L1 = L0 XOR F(R0,{label_a}) = {l0} XOR {f1_out} = {l1}. R1 = R0 = {r1} (no cambia).",
        extra={"l1": l1, "r1": r1},
    )

    sw_l, sw_r = r1, l1
    sw_step = step(
        5,
        "Intercambiar mitades (SW)",
        f"SW cambia el orden: ahora la mitad izquierda es {sw_l} y la derecha es {sw_r}.",
    )

    f2_out, f2_step = _f_function(sw_r, kb, 6, label_b)
    l2 = _xor(sw_l, f2_out)
    r2 = sw_r

    round2_step = step(
        7,
        f"Ronda 2: aplicar f{label_b}",
        f"L2 = {sw_l} XOR F({sw_r},{label_b}) = {sw_l} XOR {f2_out} = {l2}. R2 = {r2} (no cambia).",
        extra={"l2": l2, "r2": r2},
    )

    pre_final = l2 + r2
    final = _permute(pre_final, IP_INV)

    final_step = step(
        8,
        "Permutacion final (IP-1)",
        f"Se combina L2||R2 = {pre_final} y se aplica IP-1: {pre_final} -> {final}.",
        extra={"result": final},
    )

    diagram_step = step(
        9,
        "Diagrama de la red Feistel",
        "Todo el proceso anterior en un solo diagrama: cada caja F combina la mitad derecha con "
        "una subclave; el resultado se XOR-ea con la mitad izquierda; las mitades se intercambian "
        "entre rondas.",
        extra={
            "diagram_type": "feistel",
            "plaintext_bits": plaintext_bits,
            "ip_out": ip_out,
            "l0": l0, "r0": r0,
            "key_a_label": label_a, "key_a": ka,
            "f1_out": f1_out, "l1": l1, "r1": r1,
            "sw_l": sw_l, "sw_r": sw_r,
            "key_b_label": label_b, "key_b": kb,
            "f2_out": f2_out, "l2": l2, "r2": r2,
            "final": final,
        },
    )

    output_label = "Texto cifrado (8 bits)" if operation == "encrypt" else "Texto plano (8 bits)"

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation=operation,
        input_summary={"text": raw_input, "key": key10},
        output=final,
        output_label=output_label,
        steps=[keygen_step, ip_step, f1_step, round1_step, sw_step, f2_step, round2_step, final_step, diagram_step],
    )


def encrypt(plaintext8: str, key10: str) -> AlgorithmRunResult:
    return _run(plaintext8.strip(), key10.strip(), ("K1", "K2"), "encrypt", plaintext8)


def decrypt(ciphertext8: str, key10: str) -> AlgorithmRunResult:
    return _run(ciphertext8.strip(), key10.strip(), ("K2", "K1"), "decrypt", ciphertext8)
