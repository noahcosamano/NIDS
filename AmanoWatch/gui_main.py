"""
AmanoWatch GUI — Entry point
Run this instead of main.py to get the desktop window.
Requires: pip install PyQt6
"""

import sys
import threading
import queue
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from gui.main_window import MainWindow
from database.init_db import init_db
from database.edit import purge_low_severity

def main():
    init_db()
    purge_low_severity()
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
