"""
AmanoWatch GUI — Main Window
Assembles header, left nav, tab content, and right alerts panel.
"""

import time
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTabWidget, QLabel, QPushButton, QStatusBar, QFrame, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QFont, QColor, QIcon

from gui.theme import *
from gui.widgets import PulseDot, mono_label, section_label, MiniBar, h_sep, v_sep
from gui.bridge import CaptureBridge
from gui.stream_panel import StreamPanel
from gui.alerts_panel import AlertsPanel
from gui.stats_panel import StatsPanel
from gui.device_panel import DevicePanel


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AmanoWatch — Network Intrusion Detection System")
        self.setMinimumSize(1280, 780)
        self.resize(1440, 860)
        self.setStyleSheet(APP_STYLE)

        self._device_path = ""
        self._device_name = "No device selected"

        self._build_ui()
        self._start_bridge()
        self._start_clock()

    # ─────────────────────────────────────────────────────────────────────────
    # UI Construction
    # ─────────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())
        root.addWidget(h_sep())

        self._demo_banner = self._build_demo_banner()
        root.addWidget(self._demo_banner)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        body.addWidget(self._build_sidebar())
        body.addWidget(v_sep())
        body.addWidget(self._build_content(), 1)
        body.addWidget(v_sep())
        body.addWidget(self._build_right_panel())

        self._switch_tab("stream")
        root.addLayout(body, 1)
        root.addWidget(h_sep())
        root.addWidget(self._build_footer())

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = QWidget()
        hdr.setFixedHeight(58)
        hdr.setStyleSheet(
            f"background: qlineargradient(x1:0,y1:0,x2:0,y2:1,"
            f"stop:0 #0a1520, stop:1 {PANEL});"
            f"border-bottom: 1px solid {BORDER2};"
        )
        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(16, 0, 16, 0)
        lay.setSpacing(12)

        # Eye logo
        eye = QLabel("◉")
        eye.setFont(QFont("Courier New", 20, QFont.Weight.Bold))
        eye.setStyleSheet(f"color: {GREEN}; background: transparent;")
        lay.addWidget(eye)

        # Title block
        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        title_lbl = QLabel("AMANOWATCH")
        title_lbl.setFont(QFont("Courier New", 15, QFont.Weight.Black))
        title_lbl.setStyleSheet(f"color: {GREEN}; background: transparent;")
        sub_lbl = QLabel("NETWORK INTRUSION DETECTION SYSTEM")
        sub_lbl.setFont(QFont("Courier New", 7))
        sub_lbl.setStyleSheet(f"color: {TEXT_DIM}; letter-spacing:3px; background:transparent;")
        title_col.addWidget(title_lbl)
        title_col.addWidget(sub_lbl)
        lay.addLayout(title_col)

        lay.addSpacing(24)

        # Status pill
        pill = QWidget()
        pill.setStyleSheet(
            f"background: rgba(0,255,136,0.05);"
            f"border: 1px solid rgba(0,255,136,0.35);"
            f"border-radius: 2px;"
        )
        pill_lay = QHBoxLayout(pill)
        pill_lay.setContentsMargins(10, 4, 10, 4)
        pill_lay.setSpacing(6)
        pill_lay.addWidget(PulseDot(GREEN, 7))
        st = mono_label("IDS ACTIVE", size=10, color=GREEN)
        pill_lay.addWidget(st)
        lay.addWidget(pill)

        lay.addStretch()

        # Device label
        self._device_lbl = mono_label(
            f"⬡  {self._device_name}", size=10, color=CYAN)
        self._device_lbl.setStyleSheet(
            f"color:{CYAN}; background:rgba(0,212,255,0.05);"
            f"border:1px solid rgba(0,212,255,0.25); border-radius:2px;"
            f"padding: 4px 10px;"
        )
        lay.addWidget(self._device_lbl)

        # PPS
        pps_col = QVBoxLayout()
        pps_col.setSpacing(2)
        pps_col.addWidget(section_label("PKT/s"))
        self._pps_lbl = mono_label("0", size=13, color=CYAN, bold=True)
        pps_col.addWidget(self._pps_lbl)
        lay.addLayout(pps_col)

        lay.addSpacing(8)

        # Clock
        self._clock_lbl = mono_label("00:00:00", size=13, color=TEXT_DIM)
        lay.addWidget(self._clock_lbl)

        return hdr

    # ── Left sidebar ──────────────────────────────────────────────────────────
    def _build_sidebar(self):
        side = QWidget()
        side.setFixedWidth(200)
        side.setStyleSheet(f"background: {PANEL};")
        lay = QVBoxLayout(side)
        lay.setContentsMargins(0, 12, 0, 12)
        lay.setSpacing(0)

        lay.addWidget(_padded(section_label("VIEWS"), 16, 0, 4))

        self._nav_btns = {}
        for key, icon, label in (
            ("stream",  "▶", "Live Stream"),
            ("stats",   "◈", "Statistics"),
            ("devices", "⬡", "Devices"),
        ):
            btn = _NavButton(icon, label)
            btn.clicked.connect(lambda _, k=key: self._switch_tab(k))
            self._nav_btns[key] = btn
            lay.addWidget(btn)

        lay.addSpacing(12)
        lay.addWidget(h_sep())
        lay.addSpacing(12)

        # Throughput mini stats
        lay.addWidget(_padded(section_label("THROUGHPUT"), 16, 0, 6))

        self._recv_lbl  = _sidebar_stat("CAPTURED",  "0")
        self._drop_lbl  = _sidebar_stat("DROPPED",   "0")
        self._pps2_lbl  = _sidebar_stat("PKT/s",     "0")

        for w in (self._recv_lbl, self._drop_lbl, self._pps2_lbl):
            lay.addWidget(w)

        lay.addSpacing(4)
        self._pps_bar = MiniBar(GREEN)
        lay.addWidget(_padded(self._pps_bar, 16, 16, 0))

        lay.addSpacing(12)
        lay.addWidget(h_sep())
        lay.addSpacing(12)

        # Detector toggles
        lay.addWidget(_padded(section_label("DETECTORS"), 16, 0, 6))

        self._det_checks = {}
        for key, label, default in (
            ("fast_scan",   "Port Scan (Fast)", True),
            ("slow_scan",   "Port Scan (Slow)", True),
            ("sweep",       "ICMP Sweep",       True),
            ("arp",         "ARP Spoof",        True),
            ("dns_tunnel",  "DNS Tunnel",       False),
        ):
            cb = QCheckBox(label)
            cb.setChecked(default)
            cb.stateChanged.connect(lambda state, k=key: self._toggle_detector(k, state))
            self._det_checks[key] = cb
            lay.addWidget(_padded(cb, 16, 0, 0))

        lay.addStretch()
        lay.addWidget(h_sep())

        ver = mono_label("AmanoWatch  v1.0", size=8, color=TEXT_DIM)
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(ver)

        return side

    # ── Content tabs ──────────────────────────────────────────────────────────
    def _build_content(self):
        self._tabs = QTabWidget()
        self._tabs.setTabsClosable(False)
        self._tabs.setMovable(False)
        self._tabs.tabBar().hide()   # We drive tabs from sidebar

        self._stream_panel = StreamPanel()
        self._stats_panel  = StatsPanel()
        self._device_panel = DevicePanel()
        self._device_panel.device_selected.connect(self._on_device_selected)

        self._tabs.addTab(self._stream_panel, "stream")
        self._tabs.addTab(self._stats_panel,  "stats")
        self._tabs.addTab(self._device_panel, "devices")

        self._tab_index = {"stream": 0, "stats": 1, "devices": 2}
        return self._tabs

    # ── Right panel ───────────────────────────────────────────────────────────
    def _build_right_panel(self):
        self._alerts_panel = AlertsPanel()
        return self._alerts_panel

    # ── Footer / status bar ───────────────────────────────────────────────────
    def _build_footer(self):
        bar = QWidget()
        bar.setFixedHeight(24)
        bar.setStyleSheet(f"background:{PANEL}; border-top:1px solid {BORDER};")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 12, 0)
        lay.setSpacing(16)

        self._status_lbl = mono_label(
            "System ready — select a device and begin capture",
            size=9, color=TEXT_DIM)
        lay.addWidget(self._status_lbl, 1)

        self._mode_lbl = mono_label("DEMO MODE", size=9, color=ORANGE)
        lay.addWidget(self._mode_lbl)

        return bar

    # ── Demo banner ───────────────────────────────────────────────────────────
    def _build_demo_banner(self):
        banner = QWidget()
        banner.setStyleSheet(
            f"background: rgba(255,140,0,0.12);"
            f"border-bottom: 1px solid rgba(255,140,0,0.4);"
        )
        lay = QHBoxLayout(banner)
        lay.setContentsMargins(14, 6, 14, 6)
        icon = mono_label("⚠", size=12, color=ORANGE)
        msg  = mono_label(
            "DEMO MODE — No real capture running. "
            "Go to Devices, select an adapter, then click SELECT DEVICE to start live capture.",
            size=10, color=ORANGE)
        msg.setWordWrap(False)
        lay.addWidget(icon)
        lay.addSpacing(6)
        lay.addWidget(msg, 1)
        return banner

    # ─────────────────────────────────────────────────────────────────────────
    # Bridge wiring
    # ─────────────────────────────────────────────────────────────────────────
    def _start_bridge(self):
        self._bridge = CaptureBridge()
        self._bridge.packet_received.connect(self._stream_panel.on_packet)
        self._bridge.alert_fired.connect(self._alerts_panel.on_alert)
        self._bridge.stats_updated.connect(self._on_stats)
        self._bridge.start()

        from gui.bridge import REAL_CAPTURE
        if REAL_CAPTURE:
            self._demo_banner.hide()
            self._mode_lbl.setText("LIVE CAPTURE")
            self._mode_lbl.setStyleSheet(f"color:{GREEN}; background:transparent;")
        else:
            self._demo_banner.show()
            self._status_lbl.setText(
                "Running in DEMO mode — go to Devices tab to connect real capture")

    # ─────────────────────────────────────────────────────────────────────────
    # Slots
    # ─────────────────────────────────────────────────────────────────────────
    @pyqtSlot(dict)
    def _on_stats(self, snap):
        pps = snap.get("pps", 0)
        self._pps_lbl.setText(str(pps))
        self._pps2_lbl.findChild(QLabel, "val").setText(str(pps))
        self._recv_lbl.findChild(QLabel, "val").setText(
            f"{snap.get('total', 0):,}")
        self._drop_lbl.findChild(QLabel, "val").setText(
            str(snap.get("dropped", 0)))
        self._pps_bar.set_pct(min(1.0, pps / 200))
        self._stats_panel.on_stats(snap)

    @pyqtSlot(str, str)
    def _on_device_selected(self, path, name):
        self._device_path = path
        self._device_name = name
        self._device_lbl.setText(f"⬡  {name}")
        self._status_lbl.setText(f"Capturing on: {name}")
        self._demo_banner.hide()
        self._mode_lbl.setText("LIVE CAPTURE")
        self._mode_lbl.setStyleSheet(f"color:{GREEN}; background:transparent;")
        self._bridge.device_path = path
        self._bridge.start()
        self._switch_tab("stream")

    def _switch_tab(self, key):
        idx = self._tab_index.get(key, 0)
        self._tabs.setCurrentIndex(idx)
        for k, btn in self._nav_btns.items():
            btn.setActive(k == key)

    def _toggle_detector(self, key, state):
        checked = (state == Qt.CheckState.Checked.value)
        attr_map = {
            "fast_scan":  "detect_fast_scan",
            "slow_scan":  "detect_slow_scan",
            "sweep":      "detect_sweep",
            "arp":        "detect_arp",
            "dns_tunnel": "detect_dns_tunnel",
        }
        if hasattr(self._bridge, attr_map[key]):
            setattr(self._bridge, attr_map[key], checked)

    # ─────────────────────────────────────────────────────────────────────────
    # Clock
    # ─────────────────────────────────────────────────────────────────────────
    def _start_clock(self):
        t = QTimer(self)
        t.timeout.connect(self._tick_clock)
        t.start(1000)
        self._tick_clock()

    def _tick_clock(self):
        self._clock_lbl.setText(
            time.strftime("%H:%M:%S"))

    def closeEvent(self, e):
        self._bridge.stop()
        e.accept()


# ─────────────────────────────────────────────────────────────────────────────
# Helper widgets
# ─────────────────────────────────────────────────────────────────────────────
def _padded(widget, left=0, right=0, bottom=0):
    w = QWidget()
    w.setStyleSheet("background:transparent;")
    lay = QHBoxLayout(w)
    lay.setContentsMargins(left, 0, right, bottom)
    lay.addWidget(widget)
    return w


def _sidebar_stat(label, value):
    w = QWidget()
    w.setStyleSheet(f"background:transparent;")
    lay = QHBoxLayout(w)
    lay.setContentsMargins(16, 2, 16, 2)
    k = mono_label(label, size=9, color=TEXT_DIM)
    k.setFixedWidth(72)
    v = mono_label(value, size=10, color=CYAN, bold=True)
    v.setObjectName("val")
    lay.addWidget(k)
    lay.addWidget(v, 1)
    return w


class _NavButton(QPushButton):
    def __init__(self, icon: str, label: str):
        super().__init__(f"  {icon}  {label}")
        self.setFont(QFont("Segoe UI", 12))
        self.setFixedHeight(38)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._active = False
        self._refresh_style()

    def setActive(self, active: bool):
        self._active = active
        self._refresh_style()

    def _refresh_style(self):
        if self._active:
            self.setStyleSheet(f"""
                QPushButton {{
                    text-align: left;
                    padding-left: 12px;
                    background: rgba(0,255,136,0.07);
                    color: {GREEN};
                    border: none;
                    border-left: 3px solid {GREEN};
                    border-radius: 0;
                    font-size: 12px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    text-align: left;
                    padding-left: 14px;
                    background: transparent;
                    color: {TEXT_DIM};
                    border: none;
                    border-left: 3px solid transparent;
                    border-radius: 0;
                    font-size: 12px;
                }}
                QPushButton:hover {{
                    background: rgba(0,212,255,0.04);
                    color: {TEXT};
                }}
            """)