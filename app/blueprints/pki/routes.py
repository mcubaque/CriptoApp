from flask import render_template, request

from app.algorithms.pki import certificates, web_of_trust
from app.blueprints.pki import bp
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("pki/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


@bp.route("/certificados")
def certificates_page():
    return render_template("pki/certificates.html")


@bp.route("/certificados/ejecutar", methods=["POST"])
def certificates_run():
    modo = request.form.get("modo", "emitir")

    if modo == "emitir":
        result = certificates.issue_certificate(
            request.form.get("subject", ""),
            int(request.form.get("subject_e", 0) or 0),
            int(request.form.get("subject_n", 0) or 0),
            request.form.get("issuer", ""),
            int(request.form.get("issuer_d", 0) or 0),
            int(request.form.get("issuer_n", 0) or 0),
            request.form.get("valid_from", "2026-01-01"),
            request.form.get("valid_to", "2027-01-01"),
        )
    elif modo == "verificar":
        result = certificates.verify_certificate(
            request.form.get("v_subject", ""),
            request.form.get("v_issuer", ""),
            int(request.form.get("v_subject_e", 0) or 0),
            int(request.form.get("v_subject_n", 0) or 0),
            request.form.get("v_valid_from", "2026-01-01"),
            request.form.get("v_valid_to", "2027-01-01"),
            int(request.form.get("v_signature", 0) or 0),
            int(request.form.get("v_issuer_e", 0) or 0),
            int(request.form.get("v_issuer_n", 0) or 0),
        )
    else:
        result = certificates.demo_chain()

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/confianza")
def trust_page():
    return render_template("pki/trust.html")


@bp.route("/confianza/ejecutar", methods=["POST"])
def trust_run():
    result = web_of_trust.evaluate_trust(
        request.form.get("edges", ""),
        request.form.get("verificador", ""),
        request.form.get("objetivo", ""),
    )
    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)
