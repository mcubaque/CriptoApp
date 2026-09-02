from flask import render_template, request

from app.algorithms.symmetric_modern import saes, sdes
from app.blueprints.symmetric_modern import bp
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("symmetric_modern/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


@bp.route("/sdes")
def sdes_page():
    return render_template("symmetric_modern/sdes.html")


@bp.route("/sdes/ejecutar", methods=["POST"])
def sdes_run():
    modo = request.form.get("modo", "cifrar")
    bloque = request.form.get("bloque", "")
    llave = request.form.get("llave", "")
    result = sdes.encrypt(bloque, llave) if modo == "cifrar" else sdes.decrypt(bloque, llave)
    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/saes")
def saes_page():
    return render_template("symmetric_modern/saes.html")


@bp.route("/saes/ejecutar", methods=["POST"])
def saes_run():
    modo = request.form.get("modo", "cifrar")
    bloque = request.form.get("bloque", "")
    llave = request.form.get("llave", "")
    result = saes.encrypt(bloque, llave) if modo == "cifrar" else saes.decrypt(bloque, llave)
    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)
