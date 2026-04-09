"""
AmanoWatch GUI — Packet Stream Panel
Live scrolling table showing captured packets.
"""

import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QComboBox, QLabel, QLineEdit, QAbstractItemView,
    QHeaderView, QSizePolicy, QDialog, QTextEdit, QDialogButtonBox,
    QScrollArea, QCompleter
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot, QStringListModel
from PyQt6.QtGui import QColor, QFont, QBrush

from gui.theme import *
from gui.widgets import ProtoBadge, mono_label, section_label, h_sep


# ── Column definitions ────────────────────────────────────────────────────────
COLS = ["TIME", "PROTO", "SRC IP", "DST IP", "SRC PORT", "DST PORT", "FLAGS", "INFO"]
COL_WIDTHS = [80, 68, 130, 130, 75, 75, 100, 180]

MAX_ROWS    = 500    # cap of rows displayed in the table
MAX_HISTORY = 2000   # packets retained for re-filtering

# If the scrollbar is within this many pixels of the top, we consider the
# user to be "at the top" and auto-scroll to follow new packets.
AUTOSCROLL_THRESHOLD = 4


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

        payload = getattr(pkt, 'payload', None)
        payload = getattr(pkt, 'payload', None)
        if payload:
            try:
                # Try to decode as UTF-8 first. most app-layer payloads are text
                text = payload.decode('utf-8', errors='replace')
                # Replace non-printable control chars with dots, keep newlines/tabs
                cleaned = ''.join(
                    c if (c.isprintable() or c in '\n\t') else '·'
                    for c in text
                )
                # Cap length so a huge packet doesn't blow up the dialog
                if len(cleaned) > 1500:
                    cleaned = cleaned[:1500] + f"\n\n... ({len(payload)} bytes total, truncated)"
                qstr = cleaned
            except Exception:
                qstr = repr(payload[:200])
            layout.addWidget(row("PAYLOAD", qstr, GREEN))

        layout.addStretch()

        btn = QPushButton("CLOSE")
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)


# ── Stream Panel ──────────────────────────────────────────────────────────────
class StreamPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._capturing    = True
        self._proto_filter = "ALL"
        self._flag_filter  = "ALL"
        self._search       = ""
        self._pending      = []          # packets queued between timer ticks
        self._history      = []          # rolling list of all captured pkts for re-filter
        self._suggestions  = set()       # autocomplete values
        self._completer_model = QStringListModel([])

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

        # Search with autocomplete
        lay.addWidget(section_label("SEARCH:"))
        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("IP, port, protocol…")
        self._search_box.setFixedWidth(180)
        self._search_box.textChanged.connect(self._set_search)

        completer = QCompleter(self._completer_model, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self._search_box.setCompleter(completer)
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
        # Always buffer so filter changes can replay history
        self._history.append(pkt)
        if len(self._history) > MAX_HISTORY:
            self._history.pop(0)

        # Harvest autocomplete tokens
        for v in (getattr(pkt, 'src_ip', None),
                  getattr(pkt, 'dst_ip', None),
                  getattr(pkt, 'protocol', None),
                  str(getattr(pkt, 'src_port', '') or ''),
                  str(getattr(pkt, 'dst_port', '') or '')):
            if v:
                self._suggestions.add(str(v))

        if self._capturing:
            self._pending.append(pkt)

    # ── Batch flush ───────────────────────────────────────────────────────────
    def _flush(self):
        if not self._pending:
            return

        batch, self._pending = self._pending, []

        # Snapshot scroll state BEFORE inserting. New rows go in at index 0
        # (top), so if the user is at the top they want to follow the stream;
        # if they've scrolled down they want their current view preserved.
        scrollbar = self._table.verticalScrollBar()
        was_at_top = (scrollbar.value() <= AUTOSCROLL_THRESHOLD)
        prev_scroll = scrollbar.value()

        self._table.setUpdatesEnabled(False)
        self._table.setSortingEnabled(False)

        inserted = 0
        for pkt in batch:
            if not self._matches(pkt):
                continue
            self._insert_row(pkt)
            inserted += 1

        # Trim to MAX_ROWS from the bottom (oldest rows)
        overflow = self._table.rowCount() - MAX_ROWS
        if overflow > 0:
            for _ in range(overflow):
                self._table.removeRow(self._table.rowCount() - 1)

        self._table.setUpdatesEnabled(True)
        self._row_lbl.setText(f"{self._table.rowCount()} rows")

        # Preserve the user's view. If they were at the top, follow new rows;
        # otherwise shift the scrollbar down by the number of newly inserted
        # rows so the packet they were looking at stays put on screen.
        if was_at_top:
            scrollbar.setValue(0)
        elif inserted > 0:
            row_height = self._table.verticalHeader().defaultSectionSize()
            new_pos = prev_scroll + (inserted * row_height)
            scrollbar.setValue(min(new_pos, scrollbar.maximum()))

        # Refresh autocomplete model
        self._refresh_completer()

    def _refresh_completer(self):
        self._completer_model.setStringList(sorted(self._suggestions))

    def _rebuild_from_history(self):
        """Re-render the table from _history using current filters."""
        self._table.setUpdatesEnabled(False)
        self._table.setRowCount(0)
        # _insert_row prepends rows, so iterate oldest→newest to get newest on top
        shown = 0
        for pkt in self._history:
            if self._matches(pkt):
                self._insert_row(pkt)
                shown += 1
                if shown >= MAX_ROWS:
                    break
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
        payload   = getattr(pkt, 'payload', None)
        info    = ""
        if payload:
            try:    info = payload.decode('utf-8', errors='replace')
            except: info = repr(payload)

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
        self._history.clear()
        self._row_lbl.setText("0 rows")

    def _set_proto(self, v):
        self._proto_filter = v
        self._rebuild_from_history()

    def _set_flag(self, v):
        self._flag_filter = v
        self._rebuild_from_history()

    def _set_search(self, v):
        self._search = v.strip()
        self._rebuild_from_history()

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