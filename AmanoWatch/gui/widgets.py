"""
AmanoWatch GUI — Reusable widgets
"""

from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout, QFrame, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QBrush, QPen, QFont
from gui.theme import *


# ── Helpers ────────────────────────────────────────────────────────────────────
def mono_label(text="", size=11, color=TEXT, bold=False):
    lbl = QLabel(text)
    f = QFont("Courier New", size)
    f.setBold(bold)
    lbl.setFont(f)
    lbl.setStyleSheet(f"color: {color}; background: transparent;")
    return lbl


def section_label(text):
    lbl = QLabel(text)
    lbl.setFont(QFont("Courier New", 8, QFont.Weight.Bold))
    lbl.setStyleSheet(f"color: {TEXT_DIM}; letter-spacing: 3px; background: transparent;")
    return lbl


def h_sep():
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(f"color: {BORDER}; background: {BORDER};")
    line.setFixedHeight(1)
    return line


def v_sep():
    line = QFrame()
    line.setFrameShape(QFrame.Shape.VLine)
    line.setStyleSheet(f"color: {BORDER}; background: {BORDER};")
    line.setFixedWidth(1)
    return line


# ── Pulsing status dot ─────────────────────────────────────────────────────────
class PulseDot(QWidget):
    def __init__(self, color=GREEN, size=8, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._size  = size
        self._alpha = 255
        self._dir   = -4
        self.setFixedSize(size + 8, size + 8)

        timer = QTimer(self)
        timer.timeout.connect(self._tick)
        timer.start(30)

    def _tick(self):
        self._alpha += self._dir
        if self._alpha <= 60:  self._dir = 4
        if self._alpha >= 255: self._dir = -4
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QColor(self._color)
        c.setAlpha(self._alpha)
        p.setBrush(QBrush(c))
        p.setPen(Qt.PenStyle.NoPen)
        off = (self.width() - self._size) // 2
        p.drawEllipse(off, off, self._size, self._size)


# ── Protocol badge ─────────────────────────────────────────────────────────────
class ProtoBadge(QLabel):
    def __init__(self, proto: str, parent=None):
        super().__init__(proto, parent)
        bg, fg = PROTO_COLORS.get(proto, (PANEL2, TEXT_DIM))
        self.setStyleSheet(f"""
            background: {bg};
            color: {fg};
            border: 1px solid {fg}44;
            border-radius: 2px;
            padding: 1px 6px;
            font-family: "Courier New";
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 1px;
        """)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedHeight(18)


# ── Stat card ─────────────────────────────────────────────────────────────────
class StatCard(QWidget):
    def __init__(self, label: str, value: str = "0",
                 accent: str = GREEN, parent=None):
        super().__init__(parent)
        self._accent = accent
        self.setStyleSheet(f"""
            QWidget {{
                background: {PANEL};
                border: 1px solid {BORDER};
                border-top: 2px solid {accent};
                border-radius: 2px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        self._lbl = section_label(label)
        self._val = QLabel(value)
        self._val.setFont(QFont("Courier New", 22, QFont.Weight.Bold))
        self._val.setStyleSheet(f"color: {accent}; background: transparent; border: none;")

        layout.addWidget(self._lbl)
        layout.addWidget(self._val)

    def set_value(self, v):
        self._val.setText(str(v))


# ── Mini bar ──────────────────────────────────────────────────────────────────
class MiniBar(QWidget):
    def __init__(self, color=GREEN, height=4, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._pct   = 0.0
        self.setFixedHeight(height)

    def set_pct(self, pct: float):
        self._pct = max(0.0, min(1.0, pct))
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Track
        p.setBrush(QBrush(QColor(BORDER)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, self.width(), self.height(), 2, 2)
        # Fill
        if self._pct > 0:
            p.setBrush(QBrush(self._color))
            p.drawRoundedRect(0, 0, int(self.width() * self._pct), self.height(), 2, 2)


# ── Alert card ────────────────────────────────────────────────────────────────
class AlertCard(QWidget):
    clicked = pyqtSignal(str, str, str)   # severity, title, body

    _ACCENT = {"critical": RED, "warning": ORANGE, "info": CYAN}

    def __init__(self, severity: str, title: str, body: str, ts: str, parent=None):
        super().__init__(parent)
        self._severity = severity
        self._title    = title
        self._body     = body
        accent = self._ACCENT.get(severity, CYAN)

        self.setStyleSheet(f"""
            QWidget {{
                background: {PANEL};
                border: 1px solid {BORDER};
                border-left: 3px solid {accent};
                border-radius: 2px;
            }}
            QWidget:hover {{ background: {PANEL2}; }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(3)

        type_lbl = mono_label(title, size=10, color=accent, bold=True)
        body_lbl = mono_label(body,  size=10, color=TEXT_DIM)
        body_lbl.setWordWrap(True)
        ts_lbl   = mono_label(ts, size=9, color=TEXT_DIM)
        ts_lbl.setStyleSheet(f"color:{TEXT_DIM}; opacity:0.6; background:transparent;")

        layout.addWidget(type_lbl)
        layout.addWidget(body_lbl)
        layout.addWidget(ts_lbl)

    def mousePressEvent(self, e):
        self.clicked.emit(self._severity, self._title, self._body)
