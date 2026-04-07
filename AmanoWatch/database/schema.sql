CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    detector_type TEXT NOT NULL, 
    severity TEXT NOT NULL,
    src_ip TEXT,
    src_mac TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_mac TEXT,
    dst_port INTEGER,
    details TEXT,
    summary TEXT NOT NULL
)