from flask import Blueprint

bp = Blueprint("classical", __name__, url_prefix="/clasica")

from app.blueprints.classical import routes  # noqa: E402,F401
