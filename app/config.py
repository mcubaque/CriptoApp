import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg2://cripto:cripto_dev_password@localhost:5433/cripto_app",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
