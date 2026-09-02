"""Simplified biometric matching: a biometric "template" (fingerprint minutiae,
iris code, etc.) is modeled as a fixed-length bit string, matched by Hamming
distance against a threshold -- a real simplification of how systems like
Daugman's iris-code matching actually work (bit-string templates + Hamming
distance IS the real technique there, just with much longer codes).

The FAR/FRR sweep uses a small hardcoded set of illustrative genuine/impostor
similarity scores (documented as such, not derived from real biometric data)
to demonstrate the central trade-off of any biometric system.
"""
from __future__ import annotations

from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "authentication"
ALGORITHM = "biometrics"

TEMPLATE_LENGTH = 32

# Illustrative sample data (NOT real biometric measurements): Hamming distances
# typically observed between two scans of the SAME person (genuine) vs two
# DIFFERENT people (impostor), out of a 32-bit template.
GENUINE_DISTANCES = [2, 3, 4, 5, 6, 4]
IMPOSTOR_DISTANCES = [10, 12, 14, 16, 18, 20, 13]


def _validate_bits(value: str, label: str) -> str | None:
    value = value.strip()
    if not value or any(c not in "01" for c in value):
        return f"{label} debe ser una cadena de solo 0s y 1s."
    return None


def match(template_a: str, template_b: str, threshold_pct: int) -> AlgorithmRunResult:
    template_a, template_b = template_a.strip(), template_b.strip()
    err = _validate_bits(template_a, "La plantilla A") or _validate_bits(template_b, "La plantilla B")
    if not err and len(template_a) != len(template_b):
        err = f"Las dos plantillas deben tener la misma longitud ({len(template_a)} != {len(template_b)})."
    if err:
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="match",
            input_summary={"template_a": template_a, "template_b": template_b, "threshold_pct": threshold_pct},
            output=None, output_label="Resultado",
            steps=[step(1, "Validar las plantillas", err, ok=False)], error=err,
        )

    rows = []
    diff_count = 0
    for i, (a, b) in enumerate(zip(template_a, template_b)):
        differ = a != b
        if differ:
            diff_count += 1
        rows.append([i + 1, a, b, "1" if differ else "0"])

    total = len(template_a)
    similarity = round((1 - diff_count / total) * 100, 1)
    accepted = similarity >= threshold_pct

    steps = [
        step(
            1,
            "Comparar bit a bit (XOR)",
            f"Se comparan las {total} posiciones de las dos plantillas. Un XOR de 1 significa que esa "
            "posición difiere.",
            columns=["Posición", "Plantilla A", "Plantilla B", "Difieren (XOR)"],
            rows=rows,
        ),
        step(
            2,
            "Calcular la distancia de Hamming y el score de similitud",
            f"Bits distintos: {diff_count} de {total}. Similitud = (1 - {diff_count}/{total}) × 100 = {similarity}%.",
            formula=f"similitud = (1 - distancia/longitud) × 100 = {similarity}%",
        ),
        step(
            3,
            "Comparar contra el umbral",
            f"Similitud ({similarity}%) {'≥' if accepted else '<'} umbral ({threshold_pct}%): "
            + ("ACEPTAR." if accepted else "RECHAZAR."),
            ok=accepted,
        ),
    ]

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="match",
        input_summary={"template_a": template_a, "template_b": template_b, "threshold_pct": threshold_pct},
        output="ACEPTAR" if accepted else "RECHAZAR",
        output_label="Decisión",
        steps=steps,
    )


def far_frr_sweep(thresholds: list[int] | None = None) -> AlgorithmRunResult:
    if thresholds is None:
        thresholds = [95, 90, 85, 80, 75, 70, 65, 60, 55, 50]

    def similarity(distance: int) -> float:
        return (1 - distance / TEMPLATE_LENGTH) * 100

    genuine_sims = [similarity(d) for d in GENUINE_DISTANCES]
    impostor_sims = [similarity(d) for d in IMPOSTOR_DISTANCES]

    rows = []
    for t in thresholds:
        far = sum(1 for s in impostor_sims if s >= t) / len(impostor_sims) * 100
        frr = sum(1 for s in genuine_sims if s < t) / len(genuine_sims) * 100
        rows.append([f"{t}%", f"{far:.0f}%", f"{frr:.0f}%"])

    steps = [
        step(
            1,
            "Datos de ejemplo (ilustrativos, no mediciones reales)",
            f"{len(GENUINE_DISTANCES)} pares genuinos (misma persona) con distancias de Hamming bajas, "
            f"{len(IMPOSTOR_DISTANCES)} pares impostores (personas distintas) con distancias altas, "
            f"sobre plantillas de {TEMPLATE_LENGTH} bits.",
            extra={"genuine_sims": [round(s, 1) for s in genuine_sims], "impostor_sims": [round(s, 1) for s in impostor_sims]},
        ),
        step(
            2,
            "Barrer el umbral y contar falsos aceptados / falsos rechazados",
            "FAR (False Accept Rate) = % de impostores que el sistema acepta por error. "
            "FRR (False Reject Rate) = % de usuarios legítimos que el sistema rechaza por error. "
            "Los dos se mueven en direcciones opuestas al cambiar el umbral.",
            columns=["Umbral", "FAR", "FRR"],
            rows=rows,
        ),
        step(
            3,
            "El trade-off",
            "Subir el umbral (exigir más similitud) baja el FAR pero sube el FRR (más gente legítima "
            "rechazada). Bajarlo hace lo contrario. No existe un umbral que minimice ambos a la vez -- "
            "se elige según el contexto: un sistema de alta seguridad prefiere FAR bajo (aunque rechace "
            "gente real de más); un sistema de conveniencia prefiere FRR bajo.",
        ),
    ]

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="far_frr",
        input_summary={"text": "curva FAR/FRR con datos de ejemplo"},
        output="Ver tabla FAR/FRR por umbral",
        output_label="Resultado",
        steps=steps,
    )
