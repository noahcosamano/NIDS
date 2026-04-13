import sqlite3
import os
from database.paths import get_db_path

DB_PATH = os.path.join(os.path.dirname(__file__), "amanowatch.db")


def query(n=None, ip=None, mac=None, port=None, severity=None,
          detector=None, since=None, date=None):
    db_path = get_db_path()
    print(db_path)
    """
    Search detections with optional filters. Any filter left as None
    is treated as 'any value' and not included in the query.

    n: maximum number of rows to return. None means no limit.
    ip / mac / port match against EITHER source or destination.
    since: SQLite datetime modifier like '-1 hour' or '-7 days'.
    date: a date string like '2026-04-07' to match a single day.
    """
    sql = "SELECT id, timestamp, detector_type, severity, " \
          "src_ip, src_mac, src_port, dst_ip, dst_mac, dst_port, " \
          "summary, details FROM detections"
    clauses = []
    params = []

    if detector is not None:
        clauses.append("detector_type = ?")
        params.append(detector)

    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity.upper())

    if ip is not None:
        clauses.append("(src_ip = ? OR dst_ip = ?)")
        params.append(ip)
        params.append(ip)

    if mac is not None:
        clauses.append("(src_mac = ? OR dst_mac = ?)")
        params.append(mac)
        params.append(mac)

    if port is not None:
        clauses.append("(src_port = ? OR dst_port = ?)")
        params.append(port)
        params.append(port)

    if since is not None:
        clauses.append("timestamp >= datetime('now', ?)")
        params.append(since)

    if date is not None:
        start_utc, end_utc = date
        clauses.append("timestamp >= ? AND timestamp < ?")
        params.append(start_utc)
        params.append(end_utc)

    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    sql += " ORDER BY timestamp DESC"

    if n is not None:
        sql += " LIMIT ?"
        params.append(n)

    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()
    return rows