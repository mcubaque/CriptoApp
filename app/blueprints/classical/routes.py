from flask import render_template, request

from app.algorithms.classical import affine, shift, substitution, transposition
from app.blueprints.classical import bp
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("classical/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


# ---------- Shift ----------

@bp.route("/desplazamiento")
def shift_page():
    return render_template("classical/shift.html")


@bp.route("/desplazamiento/ejecutar", methods=["POST"])
def shift_run():
    modo = request.form.get("modo", "cifrar")
    texto = request.form.get("texto", "")

    if modo == "cifrar":
        llave = int(request.form.get("llave", 0) or 0)
        result = shift.encrypt(texto, llave)
    elif modo == "descifrar":
        llave = int(request.form.get("llave", 0) or 0)
        result = shift.decrypt(texto, llave)
    elif modo == "romper_fuerza":
        result = shift.crack_bruteforce(texto)
    else:
        cipher_letter = request.form.get("letra_cifrada", "A") or "A"
        plain_letter = request.form.get("letra_plana", "E") or "E"
        result = shift.crack_frequency_hypothesis(texto, cipher_letter, plain_letter)

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


# ---------- Affine ----------

@bp.route("/afin")
def affine_page():
    return render_template("classical/affine.html")


@bp.route("/afin/ejecutar", methods=["POST"])
def affine_run():
    modo = request.form.get("modo", "cifrar")
    texto = request.form.get("texto", "")

    if modo == "cifrar":
        a = int(request.form.get("a", 1) or 1)
        b = int(request.form.get("b", 0) or 0)
        result = affine.encrypt(texto, a, b)
    elif modo == "descifrar":
        a = int(request.form.get("a", 1) or 1)
        b = int(request.form.get("b", 0) or 0)
        result = affine.decrypt(texto, a, b)
    elif modo == "romper_fuerza":
        result = affine.crack_bruteforce(texto)
    else:
        result = affine.crack_frequency_hypothesis(
            texto,
            request.form.get("cipher_letter_1", "A") or "A",
            request.form.get("plain_letter_1", "e") or "e",
            request.form.get("cipher_letter_2", "B") or "B",
            request.form.get("plain_letter_2", "t") or "t",
        )

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


# ---------- Transposition ----------

@bp.route("/transposicion")
def transposition_page():
    return render_template("classical/transposition.html")


@bp.route("/transposicion/ejecutar", methods=["POST"])
def transposition_run():
    modo = request.form.get("modo", "cifrar")
    texto = request.form.get("texto", "")
    llave_raw = request.form.get("llave", "")
    try:
        llave = [int(x.strip()) for x in llave_raw.split(",") if x.strip()]
    except ValueError:
        llave = []

    if modo == "cifrar":
        result = transposition.encrypt(texto, llave)
    else:
        result = transposition.decrypt(texto, llave)

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)


# ---------- Substitution ----------

@bp.route("/sustitucion")
def substitution_page():
    return render_template("classical/substitution.html")


def _parse_mapping(raw: str) -> dict[str, str]:
    mapping = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            k, v = k.strip(), v.strip()
            if k and v:
                mapping[k[0]] = v[0]
    return mapping


@bp.route("/sustitucion/ejecutar", methods=["POST"])
def substitution_run():
    modo = request.form.get("modo", "cifrar")
    texto = request.form.get("texto", "")

    if modo == "cifrar":
        result = substitution.encrypt(texto, request.form.get("llave", ""))
    elif modo == "descifrar":
        result = substitution.decrypt(texto, request.form.get("llave", ""))
    elif modo == "auto":
        result = substitution.crack_auto(texto)
    else:
        mapping = _parse_mapping(request.form.get("mapping", ""))
        result = substitution.crack_interactive(texto, mapping)

    _maybe_save(result)
    return render_template("partials/_step_trace.html", result=result)
