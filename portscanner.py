import socket
from PyQt5.QtCore import QThread, pyqtSignal
import ui

q = ui.q

class PortScanner(QThread):
    result_signal = pyqtSignal(str, bool)

    def port_scan(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)  # 타임아웃 설정 (초 단위)

            result = s.connect_ex((host, port))
            if result == 0:
                self.result_signal.emit(f"{host:15}:{port:5} is open", True)
            else:
                self.result_signal.emit(f"{host:15}:{port:5} is closed", False)
        finally:
            s.close()

    def run(self):
        while True:
            host, port = q.get()
            self.port_scan(host, port)
            q.task_done()