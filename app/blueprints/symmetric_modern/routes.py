from flask import render_template, request

from app.algorithms.symmetric_modern import saes, sdes
from app.blueprints.symmetric_modern import bp
from app.core.code_tutor import trace_call
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("symmetric_modern/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


def _render_tutor(title, func, args=(), kwargs=None):
    tutor = trace_call(func, args, kwargs or {})
    return render_template("tutor.html", title=title, payload=tutor.to_payload())


@bp.route("/sdes")
def sdes_page():
    return render_template("symmetric_modern/sdes.html")


def _resolve_sdes(form):
    modo = form.get("modo", "cifrar")
    bloque = form.get("bloque", "")
    llave = form.get("llave", "")
    func = sdes.encrypt if modo == "cifrar" else sdes.decrypt
    return func, (bloque, llave)


@bp.route("/sdes/ejecutar", methods=["POST"])
def sdes_run():
    func, args = _resolve_sdes(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/sdes/tutor", methods=["POST"])
def sdes_tutor():
    func, args = _resolve_sdes(request.form)
    return _render_tutor("S-DES", func, args)


@bp.route("/saes")
def saes_page():
    return render_template("symmetric_modern/saes.html")


def _resolve_saes(form):
    modo = form.get("modo", "cifrar")
    bloque = form.get("bloque", "")
    llave = form.get("llave", "")
    func = saes.encrypt if modo == "cifrar" else saes.decrypt
    return func, (bloque, llave)


@bp.route("/saes/ejecutar", methods=["POST"])
def saes_run():
    func, args = _resolve_saes(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/saes/tutor", methods=["POST"])
def saes_tutor():
    func, args = _resolve_saes(request.form)
    return _render_tutor("S-AES", func, args)
