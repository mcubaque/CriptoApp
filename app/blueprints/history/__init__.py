from flask import Blueprint

bp = Blueprint("history", __name__, url_prefix="/historial")

from app.blueprints.history import routes  # noqa: E402,F401
