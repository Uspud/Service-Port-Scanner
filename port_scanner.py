import sys
import socket
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTextBrowser, QLabel, QFileDialog, QMessageBox, QComboBox
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QInputDialog
from threading import Thread, Lock
from queue import Queue
from scapy.all import *

import identify_service as ids

N_THREADS = 1000
q = Queue()
print_lock = Lock()

class PortScanner(QThread):
    result_signal = pyqtSignal(str, bool)

    def __init__(self, scan_type):
        super().__init__()
        self.scan_type = scan_type

    def port_scan(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)

            result = s.connect_ex((host, port))
            if result == 0:
                self.result_signal.emit(f"{host:15}:{port:5} is open", True)
            else:
                self.result_signal.emit(f"{host:15}:{port:5} is closed", False)
        finally:
            s.close()

    def stealth_scan(self, host, port):
        source_port = RandShort()
        p = IP(dst=host)/TCP(sport=source_port, dport=port, flags="S")
        response = sr1(p, timeout=3, verbose=0)
        
        if response:
            if response[TCP].flags == "SA":
                self.result_signal.emit(f"{host:15}:{port:5} is open", True)
                sr1(IP(dst=host)/TCP(sport=source_port, dport=port, flags="R"), timeout=1, verbose=0)
            elif response[TCP].flags == "RA":
                self.result_signal.emit(f"{host:15}:{port:5} is closed", False)
        else:
            self.result_signal.emit(f"{host:15}:{port:5} no response", False)

    def udp_scan(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(b"", (host, port))
        except socket.error as e:
            if str(e) == "ICMP Port Unreachable":
                self.result_signal.emit(f"{host:15}:{port:5} is closed", False)
            else:
                self.result_signal.emit(f"{host:15}:{port:5} is open", True)
        finally:
            s.close()

    def run(self):
        while True:
            host, port = q.get()
            if self.scan_type == "TCP Scan":
                self.port_scan(host, port)
            elif self.scan_type == "Stealth Scan (Need Permission)":
                self.stealth_scan(host, port)
            q.task_done()

class PortScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.results = {}
        self.exports = {}
        self.initUI()

    def initUI(self):
        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()

        self.host_label = QLabel("Host:")
        self.host_input = QLineEdit()
        self.port_range_label = QLabel("Port Range (Example: 1-65535):")
        self.port_range_input = QLineEdit()

        self.scan_type_label = QLabel("Scan Type:")
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["TCP Scan", "Stealth Scan (Need Permission)"])
        left_layout.addWidget(self.scan_type_label)
        left_layout.addWidget(self.scan_type_combo)

        self.scan_button = QPushButton("Start Scanning")
        self.scan_button.clicked.connect(self.start_scanning)

        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self.reset_scanner)

        self.result_box = QTextBrowser()

        self.output_button = QPushButton("Service Scan")
        self.output_button.clicked.connect(self.display_detailed_results)

        self.export_position_label = QLabel("Folder: ")
        self.export_position_input = QLineEdit()
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_detailed_data)

        left_layout.addWidget(self.host_label)
        left_layout.addWidget(self.host_input)
        left_layout.addWidget(self.port_range_label)
        left_layout.addWidget(self.port_range_input)
        left_layout.addWidget(self.scan_button)
        left_layout.addWidget(self.reset_button)
        left_layout.addWidget(self.result_box)
        left_layout.addWidget(self.output_button)
        left_layout.addWidget(self.export_position_label)
        left_layout.addWidget(self.export_position_input)
        left_layout.addWidget(self.export_button)

        right_layout = QVBoxLayout()

        self.detailed_result_label = QLabel("Result:")
        self.detailed_result_box = QTextBrowser()
        self.detailed_result_box.setFixedWidth(400)

        right_layout.addWidget(self.detailed_result_label)
        right_layout.addWidget(self.detailed_result_box)

        main_layout.addLayout(left_layout)
        main_layout.addLayout(right_layout)

        self.setLayout(main_layout)
        self.setWindowTitle("Port Scanner")

    def start_scanning(self):
        self.results = {}
        self.result_box.clear()
        domain_or_ip = self.host_input.text()
        port_range = self.port_range_input.text()
        selected_scan_type = self.scan_type_combo.currentText()

        try:
            ip_addresses = [ip[4][0] for ip in socket.getaddrinfo(domain_or_ip, None)]
        except socket.gaierror:
            QMessageBox.critical(self, "Error", f"No {domain_or_ip}")
            return

        if len(ip_addresses) > 1:
            selected_ip, ok = QInputDialog.getItem(self, "Select an IP", "Multiple IPs found. Please select one:", ip_addresses, 0, False)
            if not ok:
                return
        else:
            selected_ip = ip_addresses[0]

        try:
            start_port, end_port = map(int, port_range.split("-"))
        except ValueError:
            error_message = f"Invalid port range format. Please provide a valid range (e.g., 1-65535)."
            QMessageBox.warning(self, "Input Error", error_message)
            return

        if start_port < 1 or end_port > 65535:
            error_message = f"Invalid port range. Please provide a valid range between 1 and 65535."
            QMessageBox.warning(self, "Input Error", error_message)
            return

        ports = [p for p in range(start_port, end_port + 1)]

        for worker in ports:
            q.put((selected_ip, worker))

        for t in range(N_THREADS):
            scanner = PortScanner(selected_scan_type)
            scanner.result_signal.connect(self.update_result)
            t = Thread(target=scanner.run)
            t.daemon = True
            t.start()    

        q.join()

    def parse_services_file(self):
        filename = "services_list.txt"
        services = {}
        
        with open(filename, "r") as f:
            lines = f.readlines()
            for line in lines:
                parts = line.split()
                if not parts:
                    continue
                service_name = parts[0]
                port_protocol = parts[1].split("/")
                
                # 오류 발생시 출력하기 위한 코드 추가
                try:
                    port = int(port_protocol[0])
                except ValueError:
                    print(f"Cannot convert '{port_protocol[0]}' to integer. Full line: '{line.strip()}'")
                    continue
                    
                protocol = port_protocol[1]

                # 여기서는 TCP 서비스만 고려하도록 설정했으나, 필요에 따라 수정 가능
                if protocol == "tcp":
                    services[port] = service_name

        return services
        
    def update_result(self, result, is_open):
        if is_open:
            self.result_box.setTextColor(QColor("green"))
            port = int(result.split(":")[1].split()[0])
            self.results[port] = (result, is_open)
            self.result_box.append(result)

    def display_detailed_results(self):
        self.detailed_result_box.clear()

        services = self.parse_services_file()

        for port in sorted(self.results.keys()):
            result, is_open = self.results[port]

            self.detailed_result_box.setTextColor(QColor("green"))

            detected_service = ids.identify_service(self.host_input.text(), port)

            if detected_service == "Unknown Service":
                detected_service = services.get(port, "Unknown Service")
                if detected_service != "Unknown Service":
                    detected_service += "??"
            self.detailed_result_box.append(f"{result} ({detected_service})")

        self.detailed_result_box.setTextColor(QColor("blue"))
        self.detailed_result_box.append("Scanning Done")

    def export_detailed_data(self):
        if not self.export_position_input.text().strip():
            options = QFileDialog.options()
            filepath, _ = QFileDialog.getSaveFileName(self, "Save File", "", "Text Files (*.txt);;All Files (*)", options=options)
            if not filepath:
                return
        else:
            filepath = self.export_position_input.text().strip()

        with open(filepath, 'w') as file:
            file.write(self.detailed_result_box.toPlainText())

        QMessageBox.information(self, "Export Complete", f"Data exported successfully to {filepath}")

    def reset_scanner(self):
        self.results = {}
        self.result_box.clear()
        self.detailed_result_box.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PortScannerApp()
    window.show()
    sys.exit(app.exec())
