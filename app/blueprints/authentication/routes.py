from flask import render_template, request

from app.algorithms.authentication import biometrics, hash_demo, password_cracking
from app.blueprints.authentication import bp
from app.core.code_tutor import trace_call
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("authentication/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


def _render_tutor(title, func, args=(), kwargs=None):
    tutor = trace_call(func, args, kwargs or {})
    return render_template("tutor.html", title=title, payload=tutor.to_payload())


@bp.route("/hash")
def hash_page():
    return render_template("authentication/hash.html")


def _resolve_hash(form):
    modo = form.get("modo", "hash")
    algoritmo = form.get("algoritmo", "sha256")

    if modo == "hash":
        return hash_demo.compute_hash, (form.get("texto", ""), algoritmo)
    elif modo == "avalancha":
        return hash_demo.avalanche_demo, (form.get("texto_a", ""), form.get("texto_b", ""), algoritmo)
    else:
        return hash_demo.hmac_demo, (form.get("llave", ""), form.get("texto", ""), algoritmo)


@bp.route("/hash/ejecutar", methods=["POST"])
def hash_run():
    func, args = _resolve_hash(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/hash/tutor", methods=["POST"])
def hash_tutor():
    func, args = _resolve_hash(request.form)
    return _render_tutor("Hash y HMAC", func, args)


@bp.route("/passwords")
def passwords_page():
    return render_template("authentication/passwords.html")


def _resolve_passwords(form):
    modo = form.get("modo", "diccionario")
    algoritmo = form.get("algoritmo", "sha256")

    if modo == "diccionario":
        return password_cracking.crack_dictionary, (form.get("hash_objetivo", ""), algoritmo)
    elif modo == "fuerza_bruta":
        charset = form.get("alfabeto", "abcdefghijklmnopqrstuvwxyz")
        max_length = int(form.get("longitud", 3) or 3)
        return password_cracking.crack_bruteforce, (form.get("hash_objetivo", ""), charset, max_length, algoritmo)
    else:
        return password_cracking.salt_demo, (
            form.get("password", ""), form.get("sal_a", ""), form.get("sal_b", ""), algoritmo,
        )


@bp.route("/passwords/ejecutar", methods=["POST"])
def passwords_run():
    func, args = _resolve_passwords(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/passwords/tutor", methods=["POST"])
def passwords_tutor():
    func, args = _resolve_passwords(request.form)
    return _render_tutor("Cracking de contraseñas", func, args)


@bp.route("/biometricos")
def biometrics_page():
    return render_template("authentication/biometrics.html")


def _resolve_biometrics(form):
    modo = form.get("modo", "comparar")

    if modo == "comparar":
        return biometrics.match, (
            form.get("plantilla_a", ""), form.get("plantilla_b", ""), int(form.get("umbral", 80) or 80),
        )
    else:
        return biometrics.far_frr_sweep, ()


@bp.route("/biometricos/ejecutar", methods=["POST"])
def biometrics_run():
    func, args = _resolve_biometrics(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/biometricos/tutor", methods=["POST"])
def biometrics_tutor():
    func, args = _resolve_biometrics(request.form)
    return _render_tutor("Biométricos", func, args)
