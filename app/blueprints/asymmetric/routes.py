from flask import render_template, request

from app.algorithms.asymmetric import diffie_hellman, digital_signature, hybrid, rsa, rsa_attacks
from app.blueprints.asymmetric import bp
from app.core.code_tutor import trace_call
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("asymmetric/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


def _render_tutor(title, func, args=(), kwargs=None):
    tutor = trace_call(func, args, kwargs or {})
    return render_template("tutor.html", title=title, payload=tutor.to_payload())


@bp.route("/rsa")
def rsa_page():
    return render_template("asymmetric/rsa.html")


def _resolve_rsa(form):
    modo = form.get("modo", "keygen")

    if modo == "keygen":
        p = int(form.get("p", 0) or 0)
        q = int(form.get("q", 0) or 0)
        e = int(form.get("e", 0) or 0)
        return rsa.keygen, (p, q, e)
    elif modo == "cifrar":
        m = int(form.get("m", 0) or 0)
        e = int(form.get("e_pub", 0) or 0)
        n = int(form.get("n", 0) or 0)
        return rsa.encrypt, (m, e, n)
    else:
        c = int(form.get("c", 0) or 0)
        d = int(form.get("d", 0) or 0)
        n = int(form.get("n_dec", 0) or 0)
        return rsa.decrypt, (c, d, n)


@bp.route("/rsa/ejecutar", methods=["POST"])
def rsa_run():
    func, args = _resolve_rsa(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/rsa/tutor", methods=["POST"])
def rsa_tutor():
    func, args = _resolve_rsa(request.form)
    return _render_tutor("RSA", func, args)


@bp.route("/firmas")
def signature_page():
    return render_template("asymmetric/digital_signature.html")


def _resolve_signature(form):
    modo = form.get("modo", "firmar")
    texto = form.get("texto", "")

    if modo == "firmar":
        d = int(form.get("d", 0) or 0)
        n = int(form.get("n", 0) or 0)
        return digital_signature.sign, (texto, d, n)
    else:
        signature = int(form.get("firma", 0) or 0)
        e = int(form.get("e", 0) or 0)
        n = int(form.get("n_ver", 0) or 0)
        return digital_signature.verify, (texto, signature, e, n)


@bp.route("/firmas/ejecutar", methods=["POST"])
def signature_run():
    func, args = _resolve_signature(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/firmas/tutor", methods=["POST"])
def signature_tutor():
    func, args = _resolve_signature(request.form)
    return _render_tutor("Firmas digitales", func, args)


@bp.route("/rsa-ataques")
def rsa_attacks_page():
    return render_template("asymmetric/rsa_attacks.html")


def _resolve_rsa_attacks(form):
    modo = form.get("modo", "factorizar")

    if modo == "factorizar":
        n = int(form.get("n", 0) or 0)
        return rsa_attacks.factor_bruteforce, (n,)
    elif modo == "modulo_comun":
        n = int(form.get("n_cm", 0) or 0)
        e1 = int(form.get("e1", 0) or 0)
        c1 = int(form.get("c1", 0) or 0)
        e2 = int(form.get("e2", 0) or 0)
        c2 = int(form.get("c2", 0) or 0)
        return rsa_attacks.common_modulus_attack, (n, e1, c1, e2, c2)
    else:
        e = int(form.get("e_w", 0) or 0)
        n = int(form.get("n_w", 0) or 0)
        return rsa_attacks.wiener_attack, (e, n)


@bp.route("/rsa-ataques/ejecutar", methods=["POST"])
def rsa_attacks_run():
    func, args = _resolve_rsa_attacks(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/rsa-ataques/tutor", methods=["POST"])
def rsa_attacks_tutor():
    func, args = _resolve_rsa_attacks(request.form)
    return _render_tutor("Ataques a RSA", func, args)


@bp.route("/hibrida")
def hybrid_page():
    return render_template("asymmetric/hybrid.html")


def _resolve_hybrid(form):
    modo = form.get("modo", "cifrar")

    if modo == "cifrar":
        texto = form.get("texto", "")
        session_key = form.get("session_key", "")
        e = int(form.get("e", 0) or 0)
        n = int(form.get("n", 0) or 0)
        return hybrid.encrypt, (texto, session_key, e, n)
    else:
        encrypted_key = int(form.get("llave_cifrada", 0) or 0)
        cipher_blocks = form.get("bloques", "")
        d = int(form.get("d", 0) or 0)
        n = int(form.get("n_dec", 0) or 0)
        return hybrid.decrypt, (encrypted_key, cipher_blocks, d, n)


@bp.route("/hibrida/ejecutar", methods=["POST"])
def hybrid_run():
    func, args = _resolve_hybrid(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/hibrida/tutor", methods=["POST"])
def hybrid_tutor():
    func, args = _resolve_hybrid(request.form)
    return _render_tutor("Criptografía híbrida", func, args)


@bp.route("/diffie-hellman")
def dh_page():
    return render_template("asymmetric/diffie_hellman.html")


def _resolve_dh(form):
    p = int(form.get("p", 0) or 0)
    g = int(form.get("g", 0) or 0)
    a = int(form.get("a", 0) or 0)
    b = int(form.get("b", 0) or 0)
    return diffie_hellman.exchange, (p, g, a, b)


@bp.route("/diffie-hellman/ejecutar", methods=["POST"])
def dh_run():
    func, args = _resolve_dh(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/diffie-hellman/tutor", methods=["POST"])
def dh_tutor():
    func, args = _resolve_dh(request.form)
    return _render_tutor("Diffie-Hellman", func, args)
