import sqlite3
import os
from database.paths import get_db_path, resource_path

DB_PATH = os.path.join(os.path.dirname(__file__), "amanowatch.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

def init_db():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    with open(resource_path('database/schema.sql'), 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()