import sqlite3

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
    conn = sqlite3.connect(DB_PATH)
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