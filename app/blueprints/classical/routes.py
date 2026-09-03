from flask import render_template, request

from app.algorithms.classical import affine, shift, substitution, transposition
from app.blueprints.classical import bp
from app.core.code_tutor import trace_call
from app.core.history_service import save_operation


@bp.route("/")
def index():
    return render_template("classical/index.html")


def _maybe_save(result):
    if result.ok:
        save_operation(result)
    return result


def _render_tutor(title, func, args=(), kwargs=None):
    tutor = trace_call(func, args, kwargs or {})
    return render_template("tutor.html", title=title, payload=tutor.to_payload())


# ---------- Shift ----------

@bp.route("/desplazamiento")
def shift_page():
    return render_template("classical/shift.html")


def _resolve_shift(form):
    modo = form.get("modo", "cifrar")
    texto = form.get("texto", "")

    if modo == "cifrar":
        llave = int(form.get("llave", 0) or 0)
        return shift.encrypt, (texto, llave)
    elif modo == "descifrar":
        llave = int(form.get("llave", 0) or 0)
        return shift.decrypt, (texto, llave)
    elif modo == "romper_fuerza":
        return shift.crack_bruteforce, (texto,)
    else:
        cipher_letter = form.get("letra_cifrada", "A") or "A"
        plain_letter = form.get("letra_plana", "E") or "E"
        return shift.crack_frequency_hypothesis, (texto, cipher_letter, plain_letter)


@bp.route("/desplazamiento/ejecutar", methods=["POST"])
def shift_run():
    func, args = _resolve_shift(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/desplazamiento/tutor", methods=["POST"])
def shift_tutor():
    func, args = _resolve_shift(request.form)
    return _render_tutor("Desplazamiento", func, args)


# ---------- Affine ----------

@bp.route("/afin")
def affine_page():
    return render_template("classical/affine.html")


def _resolve_affine(form):
    modo = form.get("modo", "cifrar")
    texto = form.get("texto", "")

    if modo == "cifrar":
        a = int(form.get("a", 1) or 1)
        b = int(form.get("b", 0) or 0)
        return affine.encrypt, (texto, a, b)
    elif modo == "descifrar":
        a = int(form.get("a", 1) or 1)
        b = int(form.get("b", 0) or 0)
        return affine.decrypt, (texto, a, b)
    elif modo == "romper_fuerza":
        return affine.crack_bruteforce, (texto,)
    else:
        return affine.crack_frequency_hypothesis, (
            texto,
            form.get("cipher_letter_1", "A") or "A",
            form.get("plain_letter_1", "e") or "e",
            form.get("cipher_letter_2", "B") or "B",
            form.get("plain_letter_2", "t") or "t",
        )


@bp.route("/afin/ejecutar", methods=["POST"])
def affine_run():
    func, args = _resolve_affine(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/afin/tutor", methods=["POST"])
def affine_tutor():
    func, args = _resolve_affine(request.form)
    return _render_tutor("Afín", func, args)


# ---------- Transposition ----------

@bp.route("/transposicion")
def transposition_page():
    return render_template("classical/transposition.html")


def _resolve_transposition(form):
    modo = form.get("modo", "cifrar")
    texto = form.get("texto", "")
    llave_raw = form.get("llave", "")
    try:
        llave = [int(x.strip()) for x in llave_raw.split(",") if x.strip()]
    except ValueError:
        llave = []

    func = transposition.encrypt if modo == "cifrar" else transposition.decrypt
    return func, (texto, llave)


@bp.route("/transposicion/ejecutar", methods=["POST"])
def transposition_run():
    func, args = _resolve_transposition(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/transposicion/tutor", methods=["POST"])
def transposition_tutor():
    func, args = _resolve_transposition(request.form)
    return _render_tutor("Transposición", func, args)


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


def _resolve_substitution(form):
    modo = form.get("modo", "cifrar")
    texto = form.get("texto", "")

    if modo == "cifrar":
        return substitution.encrypt, (texto, form.get("llave", ""))
    elif modo == "descifrar":
        return substitution.decrypt, (texto, form.get("llave", ""))
    elif modo == "auto":
        return substitution.crack_auto, (texto,)
    else:
        mapping = _parse_mapping(form.get("mapping", ""))
        return substitution.crack_interactive, (texto, mapping)


@bp.route("/sustitucion/ejecutar", methods=["POST"])
def substitution_run():
    func, args = _resolve_substitution(request.form)
    result = _maybe_save(func(*args))
    return render_template("partials/_step_trace.html", result=result)


@bp.route("/sustitucion/tutor", methods=["POST"])
def substitution_tutor():
    func, args = _resolve_substitution(request.form)
    return _render_tutor("Sustitución", func, args)
