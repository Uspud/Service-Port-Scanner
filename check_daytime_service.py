import socket
import re

    
def get_time_data(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            data = s.recv(4096)
            return data
    except (socket.timeout, socket.error):
        return None

def check_ASCII_Format(ascii_data):
    pattern = r"\d{1,2} [A-Z]{3} \d{4} \d{2}:\d{2}:\d{2} UTC"
    return bool(re.match(pattern, ascii_data))

def check_daytime_service(host, port):
    data = get_time_data(host, port)
    
    if data:
        try:
            ascii_data = data.decode('utf-8', errors='replace').strip()
            if check_ASCII_Format(ascii_data):
                return True, ascii_data
            else:
                return False, None
        except UnicodeDecodeError:
            return False, None
    else:
        return False, None