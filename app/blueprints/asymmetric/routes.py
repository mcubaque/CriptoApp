from flask import render_template, request

from app.algorithms.asymmetric import diffie_hellman, digital_signature, hybrid, rsa, rsa_attacks
from app.blueprints.asymmetric import bp
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("asymmetric/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


@bp.route("/rsa")
def rsa_page():
    return render_template("asymmetric/rsa.html")


@bp.route("/rsa/ejecutar", methods=["POST"])
def rsa_run():
    modo = request.form.get("modo", "keygen")

    if modo == "keygen":
        p = int(request.form.get("p", 0) or 0)
        q = int(request.form.get("q", 0) or 0)
        e = int(request.form.get("e", 0) or 0)
        result = rsa.keygen(p, q, e)
    elif modo == "cifrar":
        m = int(request.form.get("m", 0) or 0)
        e = int(request.form.get("e_pub", 0) or 0)
        n = int(request.form.get("n", 0) or 0)
        result = rsa.encrypt(m, e, n)
    else:
        c = int(request.form.get("c", 0) or 0)
        d = int(request.form.get("d", 0) or 0)
        n = int(request.form.get("n_dec", 0) or 0)
        result = rsa.decrypt(c, d, n)

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/firmas")
def signature_page():
    return render_template("asymmetric/digital_signature.html")


@bp.route("/firmas/ejecutar", methods=["POST"])
def signature_run():
    modo = request.form.get("modo", "firmar")
    texto = request.form.get("texto", "")

    if modo == "firmar":
        d = int(request.form.get("d", 0) or 0)
        n = int(request.form.get("n", 0) or 0)
        result = digital_signature.sign(texto, d, n)
    else:
        signature = int(request.form.get("firma", 0) or 0)
        e = int(request.form.get("e", 0) or 0)
        n = int(request.form.get("n_ver", 0) or 0)
        result = digital_signature.verify(texto, signature, e, n)

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/rsa-ataques")
def rsa_attacks_page():
    return render_template("asymmetric/rsa_attacks.html")


@bp.route("/rsa-ataques/ejecutar", methods=["POST"])
def rsa_attacks_run():
    modo = request.form.get("modo", "factorizar")

    if modo == "factorizar":
        n = int(request.form.get("n", 0) or 0)
        result = rsa_attacks.factor_bruteforce(n)
    elif modo == "modulo_comun":
        n = int(request.form.get("n_cm", 0) or 0)
        e1 = int(request.form.get("e1", 0) or 0)
        c1 = int(request.form.get("c1", 0) or 0)
        e2 = int(request.form.get("e2", 0) or 0)
        c2 = int(request.form.get("c2", 0) or 0)
        result = rsa_attacks.common_modulus_attack(n, e1, c1, e2, c2)
    else:
        e = int(request.form.get("e_w", 0) or 0)
        n = int(request.form.get("n_w", 0) or 0)
        result = rsa_attacks.wiener_attack(e, n)

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/hibrida")
def hybrid_page():
    return render_template("asymmetric/hybrid.html")


@bp.route("/hibrida/ejecutar", methods=["POST"])
def hybrid_run():
    modo = request.form.get("modo", "cifrar")

    if modo == "cifrar":
        texto = request.form.get("texto", "")
        session_key = request.form.get("session_key", "")
        e = int(request.form.get("e", 0) or 0)
        n = int(request.form.get("n", 0) or 0)
        result = hybrid.encrypt(texto, session_key, e, n)
    else:
        encrypted_key = int(request.form.get("llave_cifrada", 0) or 0)
        cipher_blocks = request.form.get("bloques", "")
        d = int(request.form.get("d", 0) or 0)
        n = int(request.form.get("n_dec", 0) or 0)
        result = hybrid.decrypt(encrypted_key, cipher_blocks, d, n)

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/diffie-hellman")
def dh_page():
    return render_template("asymmetric/diffie_hellman.html")


@bp.route("/diffie-hellman/ejecutar", methods=["POST"])
def dh_run():
    p = int(request.form.get("p", 0) or 0)
    g = int(request.form.get("g", 0) or 0)
    a = int(request.form.get("a", 0) or 0)
    b = int(request.form.get("b", 0) or 0)
    result = diffie_hellman.exchange(p, g, a, b)
    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)
