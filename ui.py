import portscanner as port
from threading import Thread
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTextBrowser, QLabel, QFileDialog, QMessageBox
from PyQt5.QtGui import QColor

from queue import Queue

q = Queue()
N_THREADS = 500

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

        self.scan_button = QPushButton("Start Scanning")
        self.scan_button.clicked.connect(self.start_scanning)

        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self.reset_scanner)

        self.result_box = QTextBrowser()

        self.output_button = QPushButton("Result")
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
        self.detailed_result_box.setFixedWidth(400)  # 가로 길이 조정. 필요하면 값을 변경하세요.

        right_layout.addWidget(self.detailed_result_label)
        right_layout.addWidget(self.detailed_result_box)

        main_layout.addLayout(left_layout)  # 메인 레이아웃에 왼쪽 레이아웃 추가
        main_layout.addLayout(right_layout)  # 메인 레이아웃에 오른쪽 레이아웃 추가

        self.setLayout(main_layout)
        self.setWindowTitle("Port Scanner")

    def start_scanning(self):
        self.results = {}
        host = self.host_input.text()
        port_range = self.port_range_input.text()

        start_port, end_port = port_range.split("-")
        start_port, end_port = int(start_port.strip()), int(end_port.strip())

        ports = [p for p in range(start_port, end_port + 1)]

        for t in range(N_THREADS):
            scanner = port.PortScanner()
            scanner.result_signal.connect(self.update_result)
            t = Thread(target=scanner.run)
            t.daemon = True
            t.start()    

        for worker in ports:
            q.put((host, worker))

        q.join()

    def update_result(self, result, is_open):
        if is_open:
            self.result_box.setTextColor(QColor("green"))
            port = int(result.split(":")[1].split()[0])  # 포트 번호 추출
            self.results[port] = (result, is_open)  # 딕셔너리에 저장
        else:
            self.result_box.setTextColor(QColor("light gray"))

        self.result_box.append(result)

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

    def display_detailed_results(self):
        self.detailed_result_box.clear()

        services = self.parse_services_file()
    
        for port in sorted(self.results.keys()):
            result, is_open = self.results[port]

            if is_open:
                self.detailed_result_box.setTextColor(QColor("green"))

            service_info = services.get(port, "Unknown Service")
            self.detailed_result_box.append(f"{result} ({service_info})")

        self.detailed_result_box.setTextColor(QColor("blue"))
        self.detailed_result_box.append("Scanning Done")

    def export_detailed_data(self):
        # 폴더 경로 명시해주지 않았을 경우, 폴더 다이얼로그 표시
        if not self.export_position_input.text().strip():
            options = QFileDialog.Options()
            filepath, _ = QFileDialog.getSaveFileName(self, "Save File", "", "Text Files (*.txt);;All Files (*)", options=options)
            if not filepath:
                return
        else:
            filepath = self.export_position_input.text().strip()

        with open(filepath, 'w') as file:
            file.write(self.detailed_result_box.toPlainText())

        QMessageBox.information(self, "Export Complete", f"Data exported successfully to {filepath}")

    def reset_scanner(self):
        q.queue.clear()  # 큐 초기화
        self.results = {}  # 결과 초기화
        self.result_box.clear()  # 결과 박스 지우기
        self.detailed_result_box.clear()  # 상세 결과 박스 지우기