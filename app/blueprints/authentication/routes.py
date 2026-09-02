from flask import render_template, request

from app.algorithms.authentication import biometrics, hash_demo, password_cracking
from app.blueprints.authentication import bp
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("authentication/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


@bp.route("/hash")
def hash_page():
    return render_template("authentication/hash.html")


@bp.route("/hash/ejecutar", methods=["POST"])
def hash_run():
    modo = request.form.get("modo", "hash")
    algoritmo = request.form.get("algoritmo", "sha256")

    if modo == "hash":
        result = hash_demo.compute_hash(request.form.get("texto", ""), algoritmo)
    elif modo == "avalancha":
        result = hash_demo.avalanche_demo(
            request.form.get("texto_a", ""), request.form.get("texto_b", ""), algoritmo
        )
    else:
        result = hash_demo.hmac_demo(
            request.form.get("llave", ""), request.form.get("texto", ""), algoritmo
        )

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/passwords")
def passwords_page():
    return render_template("authentication/passwords.html")


@bp.route("/passwords/ejecutar", methods=["POST"])
def passwords_run():
    modo = request.form.get("modo", "diccionario")
    algoritmo = request.form.get("algoritmo", "sha256")

    if modo == "diccionario":
        result = password_cracking.crack_dictionary(request.form.get("hash_objetivo", ""), algoritmo)
    elif modo == "fuerza_bruta":
        charset = request.form.get("alfabeto", "abcdefghijklmnopqrstuvwxyz")
        max_length = int(request.form.get("longitud", 3) or 3)
        result = password_cracking.crack_bruteforce(
            request.form.get("hash_objetivo", ""), charset, max_length, algoritmo
        )
    else:
        result = password_cracking.salt_demo(
            request.form.get("password", ""),
            request.form.get("sal_a", ""),
            request.form.get("sal_b", ""),
            algoritmo,
        )

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/biometricos")
def biometrics_page():
    return render_template("authentication/biometrics.html")


@bp.route("/biometricos/ejecutar", methods=["POST"])
def biometrics_run():
    modo = request.form.get("modo", "comparar")

    if modo == "comparar":
        result = biometrics.match(
            request.form.get("plantilla_a", ""),
            request.form.get("plantilla_b", ""),
            int(request.form.get("umbral", 80) or 80),
        )
    else:
        result = biometrics.far_frr_sweep()

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)
