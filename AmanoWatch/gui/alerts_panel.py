"""
AmanoWatch GUI — Alerts Panel
Right sidebar: threat alerts + blocked IPs list.
"""

import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QScrollArea,
    QPushButton, QLabel, QDialog, QFrame
)
from PyQt6.QtCore import Qt, pyqtSlot

from gui.theme import *
from gui.widgets import AlertCard, mono_label, section_label, h_sep, PulseDot


MAX_ALERTS = 50


# ── Alert Detail Dialog ────────────────────────────────────────────────────────
class AlertDetailDialog(QDialog):
    def __init__(self, severity, title, body, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(420, 280)
        self.setStyleSheet(f"background:{PANEL}; color:{TEXT};")

        accent = {
            "critical": RED,
            "warning":  ORANGE,
            "info":     CYAN,
        }.get(severity, CYAN)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        hdr = QHBoxLayout()
        dot = PulseDot(color=accent)
        lbl = mono_label(title, size=13, color=accent, bold=True)
        hdr.addWidget(dot)
        hdr.addWidget(lbl)
        hdr.addStretch()
        layout.addLayout(hdr)

        sev_lbl = mono_label(f"SEVERITY: {severity.upper()}", size=10, color=accent)
        layout.addWidget(sev_lbl)
        layout.addWidget(h_sep())

        body_lbl = mono_label(body, size=11, color=TEXT)
        body_lbl.setWordWrap(True)
        layout.addWidget(body_lbl)

        ts_lbl = mono_label(
            time.strftime("Detected at %H:%M:%S on %Y-%m-%d"),
            size=9, color=TEXT_DIM
        )
        layout.addWidget(ts_lbl)
        layout.addStretch()

        btn_row = QHBoxLayout()
        dismiss = QPushButton("DISMISS")
        dismiss.clicked.connect(self.accept)
        btn_row.addStretch()
        btn_row.addWidget(dismiss)
        layout.addLayout(btn_row)


# ── Blocked IP row ─────────────────────────────────────────────────────────────
class BlockedRow(QWidget):
    def __init__(self, ip: str, remaining_sec: int, on_unblock, parent=None):
        super().__init__(parent)
        self._ip = ip
        self._remaining = remaining_sec
        self.setStyleSheet(f"""
            QWidget {{
                background: rgba(255,51,85,0.05);
                border: 1px solid rgba(255,51,85,0.2);
                border-radius: 2px;
            }}
        """)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 5, 8, 5)

        self._ip_lbl  = mono_label(ip, size=10, color=RED)
        self._tmr_lbl = mono_label(f"{remaining_sec}s", size=9, color=TEXT_DIM)

        unblock = QPushButton("UNBLOCK")
        unblock.setObjectName("danger")
        unblock.setFixedSize(70, 20)
        unblock.setFont(__import__('PyQt6').QtGui.QFont("Courier New", 8))
        unblock.clicked.connect(lambda: on_unblock(ip))

        lay.addWidget(self._ip_lbl, 1)
        lay.addWidget(self._tmr_lbl)
        lay.addWidget(unblock)

    def update_timer(self, sec):
        self._remaining = sec
        self._tmr_lbl.setText(f"{sec}s")


# ── Alerts Panel ──────────────────────────────────────────────────────────────
class AlertsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(290)
        self._alert_count  = 0
        self._blocked_ips  = {}   # ip -> expiry timestamp
        self._blocked_rows = {}   # ip -> BlockedRow widget

        self._build_ui()

        # Tick timer for blocked-IP countdown
        from PyQt6.QtCore import QTimer
        t = QTimer(self)
        t.timeout.connect(self._tick_blocked)
        t.start(1000)

    # ── Construction ──────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        hdr = QWidget()
        hdr.setStyleSheet(f"background:{PANEL}; border-bottom:1px solid {BORDER};")
        hlay = QHBoxLayout(hdr)
        hlay.setContentsMargins(12, 10, 12, 10)
        self._hdr_lbl = section_label("THREAT ALERTS")
        self._cnt_lbl = mono_label("0", size=11, color=RED, bold=True)
        hlay.addWidget(self._hdr_lbl)
        hlay.addStretch()
        hlay.addWidget(self._cnt_lbl)
        root.addWidget(hdr)

        # Scroll area for alert cards
        self._alerts_area = QScrollArea()
        self._alerts_area.setWidgetResizable(True)
        self._alerts_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._alerts_area.setStyleSheet(
            f"background:{BG}; border:none;")

        self._alerts_widget = QWidget()
        self._alerts_widget.setStyleSheet(f"background:{BG};")
        self._alerts_layout = QVBoxLayout(self._alerts_widget)
        self._alerts_layout.setContentsMargins(8, 8, 8, 8)
        self._alerts_layout.setSpacing(6)
        self._alerts_layout.addStretch()

        self._alerts_area.setWidget(self._alerts_widget)
        root.addWidget(self._alerts_area, 1)

        root.addWidget(h_sep())

        # Blocked IPs section
        blocked_hdr = QWidget()
        blocked_hdr.setStyleSheet(
            f"background:{PANEL}; border-bottom:1px solid {BORDER};")
        bhlay = QHBoxLayout(blocked_hdr)
        bhlay.setContentsMargins(12, 8, 12, 8)
        self._blocked_lbl = section_label("BLOCKED IPs")
        self._b_cnt_lbl   = mono_label("0", size=10, color=TEXT_DIM)
        bhlay.addWidget(self._blocked_lbl)
        bhlay.addStretch()
        bhlay.addWidget(self._b_cnt_lbl)
        root.addWidget(blocked_hdr)

        self._blocked_scroll = QScrollArea()
        self._blocked_scroll.setWidgetResizable(True)
        self._blocked_scroll.setFixedHeight(130)
        self._blocked_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._blocked_scroll.setStyleSheet(f"background:{PANEL}; border:none;")

        self._blocked_widget = QWidget()
        self._blocked_widget.setStyleSheet(f"background:{PANEL};")
        self._blocked_layout = QVBoxLayout(self._blocked_widget)
        self._blocked_layout.setContentsMargins(8, 6, 8, 6)
        self._blocked_layout.setSpacing(4)
        self._blocked_layout.addStretch()

        self._blocked_scroll.setWidget(self._blocked_widget)
        root.addWidget(self._blocked_scroll)

        self._empty_blocked = mono_label(
            "  No blocked IPs", size=9, color=TEXT_DIM)
        self._blocked_layout.insertWidget(0, self._empty_blocked)

    # ── Slot: receive alert ────────────────────────────────────────────────────
    @pyqtSlot(str, str, str)
    def on_alert(self, severity: str, title: str, body: str):
        ts = time.strftime("%H:%M:%S")
        card = AlertCard(severity, title, body, ts)
        card.clicked.connect(self._open_detail)

        # Insert before stretch at end
        self._alerts_layout.insertWidget(
            self._alerts_layout.count() - 1, card)

        self._alert_count += 1
        self._cnt_lbl.setText(str(self._alert_count))

        # Auto-block critical alerts
        if severity == "critical":
            # Try to parse an IP from the body
            import re
            m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', body)
            if m:
                self.block_ip(m.group(1))

        # Trim
        while self._alerts_layout.count() - 1 > MAX_ALERTS:
            item = self._alerts_layout.itemAt(0)
            if item and item.widget():
                item.widget().deleteLater()
                self._alerts_layout.removeItem(item)

        # Scroll to newest
        self._alerts_area.verticalScrollBar().setValue(
            self._alerts_area.verticalScrollBar().maximum())

    # ── Block / Unblock ───────────────────────────────────────────────────────
    def block_ip(self, ip: str, timeout: int = 300):
        self._blocked_ips[ip] = time.time() + timeout
        if ip not in self._blocked_rows:
            self._empty_blocked.hide()
            row = BlockedRow(ip, timeout, self._unblock_ip)
            self._blocked_rows[ip] = row
            self._blocked_layout.insertWidget(0, row)
            self._b_cnt_lbl.setText(str(len(self._blocked_ips)))

    def _unblock_ip(self, ip: str):
        if ip in self._blocked_ips:
            del self._blocked_ips[ip]
        if ip in self._blocked_rows:
            self._blocked_rows[ip].deleteLater()
            del self._blocked_rows[ip]
        self._b_cnt_lbl.setText(str(len(self._blocked_ips)))
        if not self._blocked_ips:
            self._empty_blocked.show()

    def _tick_blocked(self):
        now = time.time()
        expired = [ip for ip, exp in self._blocked_ips.items() if exp <= now]
        for ip in expired:
            self._unblock_ip(ip)
        for ip, row in self._blocked_rows.items():
            rem = max(0, int(self._blocked_ips[ip] - now))
            row.update_timer(rem)

    # ── Detail dialog ─────────────────────────────────────────────────────────
    def _open_detail(self, severity, title, body):
        dlg = AlertDetailDialog(severity, title, body, self)
        dlg.exec()
