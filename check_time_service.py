import socket
from datetime import datetime, timedelta

def check_time_protocol(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))
            data = s.recv(1024)

            #time protocol을 통해 받아온 데이터를 빅 엔디안 방식으로 정리
            timestamp = int.from_bytes(data, byteorder='big')
            
            #time protocol은 32비트 값으로 나타나므로 32비트인지 체크.
            if len(data) != 4:
                return False, None
            
            #32비트 값으로 나타난 숫자는 1900년 1월 1일 부터 현재까지의 초를 나타낸다.
            start_time = datetime(1900, 1, 1)
            current_time = f"Server time: {start_time + timedelta(seconds=timestamp)}"
            return True, current_time
            
    except (socket.timeout, socket.error):
        return False, None