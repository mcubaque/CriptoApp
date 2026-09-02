"""Create all database tables. Run once after `docker compose up -d db`.
Usage: python scripts/init_db.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from app import create_app
from app.extensions import db

app = create_app()
with app.app_context():
    db.create_all()
    print("Tablas creadas correctamente.")
