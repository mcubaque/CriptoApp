from flask import render_template, request

from app.blueprints.history import bp
from app.models import OperationHistory


@bp.route("/")
def index():
    family = request.args.get("family") or None
    algorithm = request.args.get("algorithm") or None

    query = OperationHistory.query
    if family:
        query = query.filter_by(family=family)
    if algorithm:
        query = query.filter_by(algorithm=algorithm)

    rows = query.order_by(OperationHistory.created_at.desc()).limit(200).all()

    families = [r[0] for r in OperationHistory.query.with_entities(OperationHistory.family).distinct()]
    algorithms = [r[0] for r in OperationHistory.query.with_entities(OperationHistory.algorithm).distinct()]

    return render_template(
        "history/index.html",
        rows=rows,
        families=sorted(families),
        algorithms=sorted(algorithms),
        selected_family=family,
        selected_algorithm=algorithm,
    )


@bp.route("/<int:row_id>")
def detail(row_id: int):
    row = OperationHistory.query.get_or_404(row_id)
    result = {
        "error": None if row.success else "Esta operación no se completó correctamente.",
        "output": row.output_text,
        "output_label": "Resultado",
        "steps": row.step_trace,
    }
    return render_template("history/_history_detail.html", row=row, result=result)
