from dotenv import load_dotenv
from flask import Flask

load_dotenv()

from app.config import Config
from app.extensions import db


def create_app(config_class: type = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    from app.blueprints.main import bp as main_bp
    from app.blueprints.classical import bp as classical_bp
    from app.blueprints.symmetric_modern import bp as symmetric_modern_bp
    from app.blueprints.asymmetric import bp as asymmetric_bp
    from app.blueprints.pki import bp as pki_bp
    from app.blueprints.authentication import bp as authentication_bp
    from app.blueprints.history import bp as history_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(classical_bp)
    app.register_blueprint(symmetric_modern_bp)
    app.register_blueprint(asymmetric_bp)
    app.register_blueprint(pki_bp)
    app.register_blueprint(authentication_bp)
    app.register_blueprint(history_bp)

    return app
