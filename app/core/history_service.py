from app.core.step_trace import AlgorithmRunResult
from app.extensions import db
from app.models import OperationHistory


def save_operation(result: AlgorithmRunResult, note: str | None = None) -> OperationHistory:
    payload = result.to_json()
    row = OperationHistory(
        family=result.family,
        algorithm=result.algorithm,
        operation=result.operation,
        input_text=payload["input_summary"].get("text") or payload["input_summary"].get("ciphertext"),
        params=payload["input_summary"],
        output_text=result.output,
        step_trace=payload["steps"],
        success=result.ok,
        note=note,
    )
    db.session.add(row)
    db.session.commit()
    return row
