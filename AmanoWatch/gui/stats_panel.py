"""
AmanoWatch GUI — Statistics Panel
Protocol distribution bars + capture metrics.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QColor, QPainter, QBrush, QPen, QLinearGradient, QFont

from gui.theme import *
from gui.widgets import StatCard, mono_label, section_label, h_sep


# ── Protocol bar ──────────────────────────────────────────────────────────────
class ProtoBar(QWidget):
    """One horizontal bar in the protocol chart."""
    HEIGHT = 22

    def __init__(self, proto: str, count: int = 0, total: int = 1, parent=None):
        super().__init__(parent)
        self._pct   = 0.0
        self._count = count
        self._proto = proto
        self._color = QColor(PROTO_COLORS.get(proto, (PANEL2, TEXT_DIM))[1])
        self.setFixedHeight(self.HEIGHT)

    def set_data(self, count: int, total: int):
        self._count = count
        self._pct   = count / max(total, 1)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W, H = self.width(), self.height()

        # Track
        p.setBrush(QBrush(QColor(BORDER)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, W, H, 3, 3)

        # Fill
        fw = max(0, int(W * self._pct))
        if fw > 0:
            grad = QLinearGradient(0, 0, fw, 0)
            c1 = QColor(self._color); c1.setAlpha(180)
            c2 = QColor(self._color); c2.setAlpha(100)
            grad.setColorAt(0, c1)
            grad.setColorAt(1, c2)
            p.setBrush(QBrush(grad))
            p.drawRoundedRect(0, 0, fw, H, 3, 3)

        # Label
        p.setPen(QPen(QColor(self._color)))
        p.setFont(QFont("Courier New", 9, QFont.Weight.Bold))
        p.drawText(6, 0, 50, H, Qt.AlignmentFlag.AlignVCenter, self._proto)

        # Count + pct
        p.setPen(QPen(QColor(TEXT_DIM)))
        p.setFont(QFont("Courier New", 9))
        right_txt = f"{self._count:,}  ({self._pct*100:.1f}%)"
        p.drawText(0, 0, W - 6, H, Qt.AlignmentFlag.AlignVCenter |
                   Qt.AlignmentFlag.AlignRight, right_txt)


# ── Stats Panel ───────────────────────────────────────────────────────────────
class StatsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._proto_bars = {}
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(16)

        # ── Top stat cards ────────────────────────────────────────────────────
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        self._card_recv    = StatCard("PACKETS RECEIVED", "0", GREEN)
        self._card_drop    = StatCard("DROPPED (BUFFER)",  "0", RED)
        self._card_pps     = StatCard("PACKETS / SEC",    "0", CYAN)
        self._card_protos  = StatCard("UNIQUE PROTOCOLS", "0", ORANGE)

        for card in (self._card_recv, self._card_drop,
                     self._card_pps, self._card_protos):
            cards_layout.addWidget(card)
        root.addLayout(cards_layout)

        root.addWidget(h_sep())

        # ── Protocol distribution ──────────────────────────────────────────────
        root.addWidget(section_label("PROTOCOL DISTRIBUTION"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"background:{BG}; border:none;")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        bars_widget = QWidget()
        bars_widget.setStyleSheet(f"background:{BG};")
        self._bars_layout = QVBoxLayout(bars_widget)
        self._bars_layout.setContentsMargins(0, 0, 0, 0)
        self._bars_layout.setSpacing(6)
        self._bars_layout.addStretch()

        scroll.setWidget(bars_widget)
        root.addWidget(scroll, 1)

        root.addWidget(h_sep())

        # ── Queue / loss row ──────────────────────────────────────────────────
        foot = QHBoxLayout()
        foot.setSpacing(24)

        for label, attr in (
            ("QUEUE SIZE",    "_foot_queue"),
            ("PACKET LOSS",   "_foot_loss"),
            ("UPTIME",        "_foot_uptime"),
        ):
            col = QVBoxLayout()
            col.setSpacing(2)
            col.addWidget(section_label(label))
            val = mono_label("—", size=14, color=TEXT_DIM)
            setattr(self, attr, val)
            col.addWidget(val)
            foot.addLayout(col)

        foot.addStretch()
        root.addLayout(foot)

        import time
        self._start_time = time.time()

    # ── Slot ──────────────────────────────────────────────────────────────────
    @pyqtSlot(dict)
    def on_stats(self, snap: dict):
        import time

        total   = snap.get("total",   0)
        dropped = snap.get("dropped", 0)
        pps     = snap.get("pps",     0)
        protos  = snap.get("protos",  {})

        self._card_recv.set_value(f"{total:,}")
        self._card_drop.set_value(f"{dropped:,}")
        self._card_pps.set_value(str(pps))
        self._card_protos.set_value(str(len(protos)))

        # Uptime
        elapsed = int(time.time() - self._start_time)
        h, rem  = divmod(elapsed, 3600)
        m, s    = divmod(rem, 60)
        self._foot_uptime.setText(f"{h:02d}:{m:02d}:{s:02d}")
        self._foot_loss.setText(
            f"{dropped/(max(total,1)+dropped)*100:.2f}%"
        )
        self._foot_queue.setText(str(snap.get("queue", 0)))

        # Bars
        proto_total = sum(protos.values()) or 1
        sorted_p = sorted(protos.items(), key=lambda x: x[1], reverse=True)

        # Add any new protocol bars
        for proto, count in sorted_p:
            if proto not in self._proto_bars:
                row = QHBoxLayout()
                lbl = mono_label(proto, size=10, color=TEXT_DIM)
                lbl.setFixedWidth(60)
                bar = ProtoBar(proto)
                row.addWidget(lbl)
                row.addWidget(bar, 1)
                # Insert before stretch
                self._bars_layout.insertLayout(
                    self._bars_layout.count() - 1, row)
                self._proto_bars[proto] = bar

        # Update all bars
        for proto, bar in self._proto_bars.items():
            bar.set_data(protos.get(proto, 0), proto_total)
