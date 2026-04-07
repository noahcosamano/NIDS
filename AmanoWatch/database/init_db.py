import sqlite3
import os

DB_PATH = "AmanoWatch/database/amanowatch.db"
SCHEMA_PATH = "AmanoWatch/database/schema.sql"

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()