from flask import Blueprint

bp = Blueprint("authentication", __name__, url_prefix="/autenticacion")

from app.blueprints.authentication import routes  # noqa: E402,F401
