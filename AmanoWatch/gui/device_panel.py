"""
AmanoWatch GUI — Device Panel
Lists available network adapters. Emits device_selected when user picks one.
Falls back to mock devices if the real DLL isn't available.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
    QPushButton, QLabel
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from gui.theme import *
from gui.widgets import mono_label, section_label, h_sep

_MOCK_DEVICES = [
    ("Intel Wi-Fi 6 AX201 160MHz",
     r"\Device\NPF_{194D9287-3B1B-4E06-B60E-5C6DE768B647}"),
    ("Realtek PCIe GbE Family Controller",
     r"\Device\NPF_{8B3F2C1A-9D42-4E67-B501-2F3A4D5E6F78}"),
    ("Loopback Pseudo-Interface",
     r"\Device\NPF_Loopback"),
    ("VMware Virtual Ethernet Adapter",
     r"\Device\NPF_{A12C4E67-1B2C-3D4E-5F67-890A1B2C3D4E}"),
]


class DevicePanel(QWidget):
    device_selected = pyqtSignal(str, str)   # (path, human_name)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._devices = []
        self._build_ui()
        self._load_devices()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        root.addWidget(section_label("AVAILABLE NETWORK INTERFACES"))
        root.addWidget(h_sep())

        self._list = QListWidget()
        self._list.setFont(QFont("Courier New", 11))
        self._list.itemDoubleClicked.connect(self._pick)
        root.addWidget(self._list, 1)

        # Info row
        self._info_lbl = mono_label(
            "Double-click a device to start capturing on it.",
            size=10, color=TEXT_DIM)
        self._info_lbl.setWordWrap(True)
        root.addWidget(self._info_lbl)

        root.addWidget(h_sep())

        btn_row = QHBoxLayout()
        refresh = QPushButton("↺  REFRESH")
        refresh.setObjectName("secondary")
        refresh.clicked.connect(self._load_devices)
        pick_btn = QPushButton("SELECT DEVICE")
        pick_btn.clicked.connect(lambda: self._pick(self._list.currentItem()))
        btn_row.addWidget(refresh)
        btn_row.addStretch()
        btn_row.addWidget(pick_btn)
        root.addLayout(btn_row)

    def _load_devices(self):
        self._list.clear()
        self._devices = []

        # Try real DLL first
        try:
            from network.get_devices import get_devices
            raw = get_devices() or ""
            entries = [e.strip() for e in raw.strip("|").split("|") if e.strip()]
            for entry in entries:
                parts = entry.split(" ", 1)
                path  = parts[0]
                name  = parts[1].strip("()") if len(parts) > 1 else path
                self._devices.append((name, path))
        except Exception:
            self._devices = list(_MOCK_DEVICES)

        for name, path in self._devices:
            item = QListWidgetItem(f"  {name}\n  {path}")
            item.setFont(QFont("Courier New", 10))
            item.setForeground(__import__('PyQt6').QtGui.QColor(TEXT))
            item.setData(Qt.ItemDataRole.UserRole, (path, name))
            self._list.addItem(item)

        if self._list.count() > 0:
            self._list.setCurrentRow(0)

        self._info_lbl.setText(
            f"{self._list.count()} device(s) found — "
            "double-click or press SELECT DEVICE."
        )

    def _pick(self, item):
        if item is None:
            item = self._list.currentItem()
        if item is None:
            return
        path, name = item.data(Qt.ItemDataRole.UserRole)
        self.device_selected.emit(path, name)
        self._info_lbl.setText(f"✔  Capturing on: {name}")
