from flask import Response, render_template

from app.blueprints.main import bp


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/robots.txt")
def robots_txt():
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")
