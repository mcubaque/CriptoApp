from flask import render_template, request

from app.algorithms.pki import certificates, web_of_trust
from app.blueprints.pki import bp
from app.core.code_tutor import trace_call
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("pki/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


def _render_tutor(title, func, args=(), kwargs=None):
    tutor = trace_call(func, args, kwargs or {})
    return render_template("tutor.html", title=title, payload=tutor.to_payload())


@bp.route("/certificados")
def certificates_page():
    return render_template("pki/certificates.html")


def _resolve_certificates(form):
    modo = form.get("modo", "emitir")

    if modo == "emitir":
        return certificates.issue_certificate, (
            form.get("subject", ""),
            int(form.get("subject_e", 0) or 0),
            int(form.get("subject_n", 0) or 0),
            form.get("issuer", ""),
            int(form.get("issuer_d", 0) or 0),
            int(form.get("issuer_n", 0) or 0),
            form.get("valid_from", "2026-01-01"),
            form.get("valid_to", "2027-01-01"),
        )
    elif modo == "verificar":
        return certificates.verify_certificate, (
            form.get("v_subject", ""),
            form.get("v_issuer", ""),
            int(form.get("v_subject_e", 0) or 0),
            int(form.get("v_subject_n", 0) or 0),
            form.get("v_valid_from", "2026-01-01"),
            form.get("v_valid_to", "2027-01-01"),
            int(form.get("v_signature", 0) or 0),
            int(form.get("v_issuer_e", 0) or 0),
            int(form.get("v_issuer_n", 0) or 0),
        )
    else:
        return certificates.demo_chain, ()


@bp.route("/certificados/ejecutar", methods=["POST"])
def certificates_run():
    func, args = _resolve_certificates(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/certificados/tutor", methods=["POST"])
def certificates_tutor():
    func, args = _resolve_certificates(request.form)
    return _render_tutor("Certificados digitales", func, args)


@bp.route("/confianza")
def trust_page():
    return render_template("pki/trust.html")


def _resolve_trust(form):
    return web_of_trust.evaluate_trust, (
        form.get("edges", ""),
        form.get("verificador", ""),
        form.get("objetivo", ""),
    )


@bp.route("/confianza/ejecutar", methods=["POST"])
def trust_run():
    func, args = _resolve_trust(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/confianza/tutor", methods=["POST"])
def trust_tutor():
    func, args = _resolve_trust(request.form)
    return _render_tutor("Anillos de confianza", func, args)
