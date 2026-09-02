from flask import Blueprint

bp = Blueprint("symmetric_modern", __name__, url_prefix="/simetrica-moderna")

from app.blueprints.symmetric_modern import routes  # noqa: E402,F401
