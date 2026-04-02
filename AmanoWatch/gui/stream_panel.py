"""
AmanoWatch GUI — Packet Stream Panel
Live scrolling table showing captured packets.
"""

import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QComboBox, QLabel, QLineEdit, QAbstractItemView,
    QHeaderView, QSizePolicy, QDialog, QTextEdit, QDialogButtonBox,
    QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QColor, QFont, QBrush

from gui.theme import *
from gui.widgets import ProtoBadge, mono_label, section_label, h_sep


# ── Column definitions ────────────────────────────────────────────────────────
COLS = ["TIME", "PROTO", "SRC IP", "DST IP", "SRC PORT", "DST PORT", "FLAGS", "INFO"]
COL_WIDTHS = [80, 68, 130, 130, 75, 75, 100, 180]

MAX_ROWS = 500   # cap before old rows are dropped


# ── Packet Detail Dialog ───────────────────────────────────────────────────────
class PacketDetailDialog(QDialog):
    def __init__(self, pkt, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Detail")
        self.setMinimumSize(480, 380)
        self.setStyleSheet(f"background:{PANEL}; color:{TEXT};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        title = mono_label(f"[ {getattr(pkt,'protocol','?')} ] PACKET DETAIL",
                           size=12, color=GREEN, bold=True)
        layout.addWidget(title)
        layout.addWidget(h_sep())

        def row(key, val, color=TEXT):
            w = QWidget()
            w.setStyleSheet("background:transparent;")
            h = QHBoxLayout(w)
            h.setContentsMargins(0,2,0,2)
            k = mono_label(key, size=10, color=TEXT_DIM)
            k.setFixedWidth(110)
            v = mono_label(str(val) if val is not None else "—", size=10, color=color)
            v.setWordWrap(True)
            h.addWidget(k)
            h.addWidget(v, 1)
            return w

        proto = getattr(pkt, 'protocol', '?')
        bg, fg = PROTO_COLORS.get(proto, (PANEL2, TEXT_DIM))

        layout.addWidget(row("PROTOCOL",  proto,                  fg))
        layout.addWidget(row("TIMESTAMP", _fmt_ts(getattr(pkt,'timestamp',0))))
        layout.addWidget(h_sep())
        layout.addWidget(row("SRC IP",    getattr(pkt,'src_ip',  '—')))
        layout.addWidget(row("DST IP",    getattr(pkt,'dst_ip',  '—')))
        layout.addWidget(row("SRC PORT",  getattr(pkt,'src_port','—')))
        layout.addWidget(row("DST PORT",  getattr(pkt,'dst_port','—')))
        layout.addWidget(row("SRC MAC",   getattr(pkt,'src_mac', '—'), TEXT_DIM))
        layout.addWidget(row("DST MAC",   getattr(pkt,'dst_mac', '—'), TEXT_DIM))
        layout.addWidget(h_sep())
        layout.addWidget(row("FLAGS",     getattr(pkt,'flags',   '—'), ORANGE))
        layout.addWidget(row("TYPE", getattr(pkt,'type',    '—'), YELLOW))

        query = getattr(pkt, 'query', None)
        if query:
            try:    qstr = query.decode('utf-8', errors='replace')
            except: qstr = repr(query)
            layout.addWidget(row("PAYLOAD", qstr, GREEN))

        layout.addStretch()

        btn = QPushButton("CLOSE")
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)


# ── Stream Panel ──────────────────────────────────────────────────────────────
class StreamPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._capturing   = True
        self._proto_filter= "ALL"
        self._flag_filter = "ALL"
        self._search      = ""
        self._pending     = []   # packets queued between timer ticks
        self._row_count   = 0

        self._build_ui()

        # Batch-insert timer — 60 ms gives ~16 fps UI updates without hammering Qt
        self._flush_timer = QTimer(self)
        self._flush_timer.timeout.connect(self._flush)
        self._flush_timer.start(60)

    # ── UI construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_toolbar())
        root.addWidget(h_sep())
        root.addWidget(self._build_table(), 1)
        root.addWidget(h_sep())
        root.addWidget(self._build_statusbar())

    def _build_toolbar(self):
        bar = QWidget()
        bar.setStyleSheet(f"background:{PANEL}; border-bottom:1px solid {BORDER};")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(8)

        # Protocol filter
        lay.addWidget(section_label("PROTO:"))
        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["ALL","TCP","UDP","ICMP","DNS","HTTP",
                                    "HTTPS","TLS","ARP","DHCP","QUIC"])
        self._proto_combo.setFixedWidth(90)
        self._proto_combo.currentTextChanged.connect(self._set_proto)
        lay.addWidget(self._proto_combo)

        lay.addSpacing(8)

        # Flag filter
        lay.addWidget(section_label("FLAGS:"))
        self._flag_combo = QComboBox()
        self._flag_combo.addItems(["ALL","SYN","ACK","FIN","RST","PSH","URG"])
        self._flag_combo.setFixedWidth(80)
        self._flag_combo.currentTextChanged.connect(self._set_flag)
        lay.addWidget(self._flag_combo)

        lay.addSpacing(8)

        # Search
        lay.addWidget(section_label("SEARCH:"))
        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("IP, port, protocol…")
        self._search_box.setFixedWidth(160)
        self._search_box.textChanged.connect(self._set_search)
        lay.addWidget(self._search_box)

        lay.addStretch()

        self._cap_btn = QPushButton("⏸  PAUSE")
        self._cap_btn.setFixedWidth(110)
        self._cap_btn.clicked.connect(self._toggle_capture)
        lay.addWidget(self._cap_btn)

        clr = QPushButton("⊘  CLEAR")
        clr.setObjectName("secondary")
        clr.setFixedWidth(90)
        clr.clicked.connect(self._clear)
        lay.addWidget(clr)

        return bar

    def _build_table(self):
        self._table = QTableWidget(0, len(COLS))
        self._table.setHorizontalHeaderLabels(COLS)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setSortingEnabled(False)
        self._table.setWordWrap(False)
        self._table.verticalHeader().setDefaultSectionSize(24)

        hdr = self._table.horizontalHeader()
        for i, w in enumerate(COL_WIDTHS):
            hdr.resizeSection(i, w)
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)

        self._table.cellDoubleClicked.connect(self._open_detail)
        return self._table

    def _build_statusbar(self):
        bar = QWidget()
        bar.setStyleSheet(f"background:{PANEL}; padding: 3px 10px;")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(8, 4, 8, 4)

        self._status_lbl = mono_label("Ready — double-click a row for details",
                                      size=9, color=TEXT_DIM)
        self._row_lbl    = mono_label("0 packets", size=9, color=TEXT_DIM)
        lay.addWidget(self._status_lbl, 1)
        lay.addWidget(self._row_lbl)
        return bar

    # ── Slot: receive packet from bridge ─────────────────────────────────────
    @pyqtSlot(object)
    def on_packet(self, pkt):
        if self._capturing:
            self._pending.append(pkt)

    # ── Batch flush ───────────────────────────────────────────────────────────
    def _flush(self):
        if not self._pending:
            return

        batch, self._pending = self._pending, []

        self._table.setUpdatesEnabled(False)
        self._table.setSortingEnabled(False)

        for pkt in batch:
            if not self._matches(pkt):
                continue
            self._insert_row(pkt)

        # Trim to MAX_ROWS
        overflow = self._table.rowCount() - MAX_ROWS
        if overflow > 0:
            for _ in range(overflow):
                self._table.removeRow(self._table.rowCount() - 1)

        self._table.setUpdatesEnabled(True)
        self._row_lbl.setText(f"{self._table.rowCount()} rows")

    def _insert_row(self, pkt):
        proto   = getattr(pkt, 'protocol', '?') or '?'
        src_ip  = getattr(pkt, 'src_ip',   '') or ''
        dst_ip  = getattr(pkt, 'dst_ip',   '') or ''
        src_p   = str(getattr(pkt, 'src_port', '') or '')
        dst_p   = str(getattr(pkt, 'dst_port', '') or '')
        flags   = getattr(pkt, 'flags',    '') or ''
        ts      = _fmt_ts(getattr(pkt, 'timestamp', 0))
        query   = getattr(pkt, 'query', None)
        info    = ""
        if query:
            try:    info = query.decode('utf-8', errors='replace')
            except: info = repr(query)

        self._table.insertRow(0)
        self._table.setItem(0, 0, _item(ts,     TEXT_DIM))
        self._table.setItem(0, 1, _item(proto))
        self._table.setItem(0, 2, _item(src_ip))
        self._table.setItem(0, 3, _item(dst_ip))
        self._table.setItem(0, 4, _item(src_p,  TEXT_DIM))
        self._table.setItem(0, 5, _item(dst_p,  TEXT_DIM))
        self._table.setItem(0, 6, _item(flags,  ORANGE if flags else TEXT_DIM))
        self._table.setItem(0, 7, _item(info,   TEXT_DIM))

        # Colour the proto cell background
        bg, fg = PROTO_COLORS.get(proto, (PANEL, TEXT_DIM))
        cell = self._table.item(0, 1)
        cell.setBackground(QBrush(QColor(bg)))
        cell.setForeground(QBrush(QColor(fg)))
        cell.setFont(QFont("Courier New", 10, QFont.Weight.Bold))
        cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        # Store full packet on the time cell for the detail dialog
        self._table.item(0, 0).setData(Qt.ItemDataRole.UserRole, pkt)

    # ── Filter logic ─────────────────────────────────────────────────────────
    def _matches(self, pkt) -> bool:
        proto = (getattr(pkt, 'protocol', '') or '').upper()
        flags = (getattr(pkt, 'flags',    '') or '').upper()
        src   = str(getattr(pkt, 'src_ip',   '') or '')
        dst   = str(getattr(pkt, 'dst_ip',   '') or '')
        sp    = str(getattr(pkt, 'src_port', '') or '')
        dp    = str(getattr(pkt, 'dst_port', '') or '')

        if self._proto_filter != "ALL":
            pf = self._proto_filter
            if pf == "HTTP":
                if proto not in ("HTTP", "HTTPS"): return False
            else:
                if proto != pf: return False

        if self._flag_filter != "ALL":
            if self._flag_filter not in flags: return False

        if self._search:
            needle = self._search.lower()
            haystack = " ".join([proto, src, dst, sp, dp, flags]).lower()
            if needle not in haystack: return False

        return True

    # ── Controls ──────────────────────────────────────────────────────────────
    def _toggle_capture(self):
        self._capturing = not self._capturing
        if self._capturing:
            self._cap_btn.setText("⏸  PAUSE")
            self._cap_btn.setObjectName("")
        else:
            self._cap_btn.setText("▶  RESUME")
            self._cap_btn.setObjectName("danger")
        self._cap_btn.setStyle(self._cap_btn.style())

    def _clear(self):
        self._table.setRowCount(0)
        self._row_lbl.setText("0 rows")

    def _set_proto(self, v):  self._proto_filter = v
    def _set_flag(self, v):   self._flag_filter  = v
    def _set_search(self, v): self._search = v.strip()

    def _open_detail(self, row, _col):
        item = self._table.item(row, 0)
        if item is None: return
        pkt = item.data(Qt.ItemDataRole.UserRole)
        if pkt is None: return
        dlg = PacketDetailDialog(pkt, self)
        dlg.exec()


# ── Helpers ────────────────────────────────────────────────────────────────────
def _item(text: str, color: str = TEXT) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    it.setForeground(QBrush(QColor(color)))
    it.setFont(QFont("Courier New", 11))
    return it


def _fmt_ts(ts: float) -> str:
    try:
        import datetime
        dt = datetime.datetime.fromtimestamp(ts)
        return dt.strftime("%H:%M:%S.") + f"{dt.microsecond//1000:03d}"
    except Exception:
        return "—"
