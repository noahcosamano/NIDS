import os
import sys
from pathlib import Path


def get_db_path():
    """Persistent, writable location for the database."""
    app_dir = Path(os.getenv('APPDATA')) / 'AmanoWatch'
    app_dir.mkdir(parents=True, exist_ok=True)
    return str(app_dir / 'amanowatch.db')


def resource_path(relative_path):
    """Read-only bundled resources (schema.sql, mmdb, etc.)."""
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        # Go up from database/ to project root
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)