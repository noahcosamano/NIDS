"""
AmanoWatch — Theme
All QSS stylesheets and color constants in one place.
"""

# ── Palette ───────────────────────────────────────────────────────────────────
BG          = "#050a0e"
PANEL       = "#090f14"
PANEL2      = "#0b1520"
BORDER      = "#0d2233"
BORDER2     = "#0a3050"
GREEN       = "#00ff88"
GREEN2      = "#00cc66"
CYAN        = "#00d4ff"
RED         = "#ff3355"
ORANGE      = "#ff8c00"
YELLOW      = "#ffd700"
TEXT        = "#c8e8ff"
TEXT_DIM    = "#4a7a99"
DIM         = "#1a3a50"
PURPLE      = "#c87dff"

# Protocol badge colours  (bg, fg)
PROTO_COLORS = {
    "TCP":   ("#0d2a35", CYAN),
    "UDP":   ("#2a1a00", ORANGE),
    "ICMP":  ("#2a2400", YELLOW),
    "ARP":   ("#1e0d35", PURPLE),
    "DNS":   ("#002a18", GREEN),
    "HTTP":  ("#2a0a0d", RED),
    "HTTPS": ("#002a15", GREEN2),
    "TLS":   ("#002a15", GREEN2),
    "QUIC":  ("#2a1a00", ORANGE),
    "DHCP":  ("#001a2a", CYAN),
    "SNMP":  ("#2a1500", ORANGE),
    "SMTP":  ("#2a0d00", "#ff6633"),
    "FTP":   ("#2a1500", ORANGE),
    "TFTP":  ("#1a2000", "#aacc00"),
    "NFS":   ("#1a1a2a", "#8888ff"),
    "TELNET":("#2a0a0d", RED),
    "POP3":  ("#2a0a15", "#ff6699"),
}

# ── Full application stylesheet ────────────────────────────────────────────────
APP_STYLE = f"""
/* ── Base ── */
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: "Segoe UI", "SF Pro Display", sans-serif;
    font-size: 12px;
    border: none;
    outline: none;
}}

QMainWindow {{
    background-color: {BG};
}}

/* ── Splitter ── */
QSplitter::handle {{
    background-color: {BORDER};
    width: 2px;
    height: 2px;
}}

/* ── Scroll bars ── */
QScrollBar:vertical {{
    background: {PANEL};
    width: 6px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {BORDER2};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ height: 6px; background: {PANEL}; border: none; }}
QScrollBar::handle:horizontal {{ background: {BORDER2}; border-radius: 3px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Tab bar ── */
QTabWidget::pane {{
    border: none;
    background: {BG};
}}
QTabBar::tab {{
    background: {PANEL};
    color: {TEXT_DIM};
    padding: 8px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    font-family: "Courier New", monospace;
    font-size: 11px;
    letter-spacing: 1px;
}}
QTabBar::tab:selected {{
    color: {GREEN};
    border-bottom: 2px solid {GREEN};
    background: {PANEL};
}}
QTabBar::tab:hover:!selected {{
    color: {TEXT};
    background: {PANEL2};
}}
QTabWidget::tab-bar {{ alignment: left; }}

/* ── Table ── */
QTableWidget {{
    background-color: {BG};
    gridline-color: {BORDER};
    border: none;
    selection-background-color: rgba(0, 212, 255, 0.1);
    selection-color: {TEXT};
    alternate-background-color: {PANEL};
    font-family: "Courier New", monospace;
    font-size: 11px;
}}
QTableWidget::item {{
    padding: 4px 8px;
    border-bottom: 1px solid {BORDER};
}}
QTableWidget::item:selected {{
    background-color: rgba(0,212,255,0.1);
    color: {TEXT};
}}
QHeaderView::section {{
    background-color: {PANEL2};
    color: {TEXT_DIM};
    padding: 6px 8px;
    border: none;
    border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER2};
    font-family: "Courier New", monospace;
    font-size: 9px;
    letter-spacing: 2px;
    font-weight: bold;
}}
QHeaderView::section:last {{ border-right: none; }}

/* ── List widget ── */
QListWidget {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 2px;
}}
QListWidget::item {{
    padding: 6px 10px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT_DIM};
}}
QListWidget::item:selected {{
    background: rgba(0,255,136,0.08);
    color: {GREEN};
}}
QListWidget::item:hover {{
    background: rgba(0,212,255,0.05);
    color: {TEXT};
}}

/* ── Push buttons ── */
QPushButton {{
    background-color: rgba(0,255,136,0.08);
    color: {GREEN};
    border: 1px solid rgba(0,255,136,0.4);
    padding: 7px 18px;
    border-radius: 2px;
    font-family: "Courier New", monospace;
    font-size: 11px;
    letter-spacing: 1px;
}}
QPushButton:hover {{
    background-color: rgba(0,255,136,0.15);
    border-color: {GREEN};
}}
QPushButton:pressed {{
    background-color: rgba(0,255,136,0.25);
}}
QPushButton:disabled {{
    color: {TEXT_DIM};
    border-color: {BORDER2};
    background: transparent;
}}
QPushButton#danger {{
    background-color: rgba(255,51,85,0.08);
    color: {RED};
    border: 1px solid rgba(255,51,85,0.4);
}}
QPushButton#danger:hover {{
    background-color: rgba(255,51,85,0.18);
    border-color: {RED};
}}
QPushButton#secondary {{
    background-color: transparent;
    color: {TEXT_DIM};
    border: 1px solid {BORDER2};
}}
QPushButton#secondary:hover {{
    color: {TEXT};
    border-color: {TEXT_DIM};
}}

/* ── ComboBox ── */
QComboBox {{
    background: {PANEL2};
    color: {TEXT};
    border: 1px solid {BORDER2};
    padding: 5px 10px;
    border-radius: 2px;
    font-family: "Courier New", monospace;
    font-size: 11px;
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox::down-arrow {{ image: none; }}
QComboBox QAbstractItemView {{
    background: {PANEL2};
    border: 1px solid {BORDER2};
    color: {TEXT};
    selection-background-color: {DIM};
}}

/* ── Line edit ── */
QLineEdit {{
    background: {PANEL2};
    color: {TEXT};
    border: 1px solid {BORDER2};
    padding: 6px 10px;
    border-radius: 2px;
    font-family: "Courier New", monospace;
    font-size: 11px;
}}
QLineEdit:focus {{
    border-color: {CYAN};
}}

/* ── Group box ── */
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 2px;
    margin-top: 12px;
    padding-top: 8px;
    color: {TEXT_DIM};
    font-family: "Courier New", monospace;
    font-size: 9px;
    letter-spacing: 2px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    color: {TEXT_DIM};
}}

/* ── Label ── */
QLabel {{ background: transparent; }}
QLabel#heading {{
    font-family: "Courier New", monospace;
    font-size: 9px;
    letter-spacing: 3px;
    color: {TEXT_DIM};
}}
QLabel#value {{
    font-family: "Courier New", monospace;
    font-size: 20px;
    font-weight: bold;
    color: {GREEN};
}}
QLabel#value_red  {{ color: {RED};    font-family: "Courier New", monospace; font-size: 20px; font-weight: bold; }}
QLabel#value_cyan {{ color: {CYAN};   font-family: "Courier New", monospace; font-size: 20px; font-weight: bold; }}
QLabel#value_orange {{ color: {ORANGE}; font-family: "Courier New", monospace; font-size: 20px; font-weight: bold; }}

/* ── Check box ── */
QCheckBox {{
    color: {TEXT_DIM};
    font-size: 12px;
    spacing: 8px;
}}
QCheckBox:hover {{ color: {TEXT}; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {BORDER2};
    background: {PANEL};
    border-radius: 2px;
}}
QCheckBox::indicator:checked {{
    background: {GREEN2};
    border-color: {GREEN};
}}

/* ── Tooltip ── */
QToolTip {{
    background: {PANEL2};
    color: {TEXT};
    border: 1px solid {BORDER2};
    padding: 4px 8px;
    font-family: "Courier New", monospace;
    font-size: 11px;
}}

/* ── Status bar ── */
QStatusBar {{
    background: {PANEL2};
    color: {TEXT_DIM};
    border-top: 1px solid {BORDER};
    font-family: "Courier New", monospace;
    font-size: 10px;
}}
QStatusBar::item {{ border: none; }}
"""
