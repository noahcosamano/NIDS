import sqlite3
from database.paths import get_db_path

DB_PATH = "AmanoWatch/database/amanowatch.db"


def add_detection(detector_type, severity, summary,
                  src_ip=None, src_mac=None, src_port=None,
                  dst_ip=None, dst_mac=None, dst_port=None,
                  details=None):
    """
    Insert a detection row. Only detector_type, severity, and summary
    are required. The timestamp column is filled in automatically by
    SQLite via the DEFAULT clause — never pass it.
    """
    conn = sqlite3.connect(get_db_path())
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO detections (
            detector_type,
            severity,
            summary,
            src_ip,
            src_mac,
            src_port,
            dst_ip,
            dst_mac,
            dst_port,
            details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        detector_type,
        severity,
        summary,
        src_ip,
        src_mac,
        src_port,
        dst_ip,
        dst_mac,
        dst_port,
        details,
    ))

    conn.commit()
    conn.close()
    
def purge_low_severity():
    conn = sqlite3.connect(get_db_path())
    try:
        cur = conn.execute(
            "DELETE FROM detections WHERE LOWER(severity) IN (?, ?)",
            ("info", "low")
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()