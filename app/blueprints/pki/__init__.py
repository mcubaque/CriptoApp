from flask import Blueprint

bp = Blueprint("pki", __name__, url_prefix="/pki")

from app.blueprints.pki import routes  # noqa: E402,F401
