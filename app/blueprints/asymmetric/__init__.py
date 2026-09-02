from flask import Blueprint

bp = Blueprint("asymmetric", __name__, url_prefix="/asimetrica")

from app.blueprints.asymmetric import routes  # noqa: E402,F401
