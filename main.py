import sys
from PyQt5.QtWidgets import QApplication
from threading import Lock
import ui

print_lock = Lock()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ui.PortScannerApp()
    window.show()
    sys.exit(app.exec_())