import socket
import http.client

import check_ftp_service as cfs
import check_ssh_service as check_ssh
import check_ssl_service as check_ssl
import check_smtp_service as check_smtp
import check_dns_service as check_dns
import check_echo_service as check_echo
import check_time_service as check_time
import check_daytime_service as check_daytime

import get_ASN1_packet as get_ASN1
import get_server_header as get_server

def is_binary_data(data):
    textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x7f)) | {0xB2})
    return bool(data.translate(None, textchars))

def check_http_service(host, port):
    try:
        connection = http.client.HTTPConnection(host, port, timeout=3)
        connection.request("GET", "/")
        response = connection.getresponse()
        connection.close()
        server = get_server.extract_server_headers(host, port)
        return True, f"{response.status} - {server}"
    except Exception as e:
        return False, str(e)

def check_tcp_service(host, port):
    # TCP 연결 시도
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # 연결 시도에 대한 타임아웃 설정
            s.connect((host, port))
            s.settimeout(3)
            
            data = s.recv(1024)

            if is_binary_data(data):
                bin_data = ''.join(f'\\x{byte:02x}' for byte in data)
            data = data.decode("utf-8", errors="replace").casefold()

            # SSH 예시와 같이 데이터를 기반으로 서비스 식별
            if "SSH".casefold() in data:
                if check_ssh.can_connect_ssh(host, port):
                    return True, "SSH"

            elif "SMTP".casefold() in data:
                if check_smtp.can_connect_smtp(host, port):
                    return True, "SMTP"
            
            elif "MYSQL".casefold() in data:
                return True, "MySQL"
            
            elif "FileZilla".casefold() in data or "ftp".casefold() in data:
                if cfs.is_ftp_service(host, port):
                    return True, "FTP"
            
            elif "ZSA".casefold() in data:
                return True, "Filezilla-admin"
            
            elif "dovecot" in data:
                return True, "dovecot"

            elif "PopPass".casefold() in data:
                return True, "Pop3PW"

            elif "POP3".casefold() in data:
                return True, "POP3"
            
            elif "IMAP4".casefold() in data:
                return True, "IMAP4"
            
            elif "postgre" in data:
                return True, "PostgreSQL"
            
            elif "mariadb" in data:
                return True, "MariaDB"
            
            elif "zsa" in data:
                return True, "Filezilla-Admin"
            
            elif "\\xff\\xfd\\x18\\xff\\xfd\\x20\\xff" in bin_data:
                return True, "Telnet"

            return False, None
        
    except Exception as e:
        return False, False

def send_request(host, port):
    response = ""

    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(("\r\n").encode())

            chunk = s.recv(4096)
            response += chunk.decode("utf-8", errors="ignore").casefold()

            if "hl7".casefold() in response:
                return True, "hl7"
            elif "RFB".casefold() in response:
                return True, "RFB"
            elif "Login:".casefold() in response and "Name:".casefold() in response:
                return True, "finger"
            elif "ABCDEFGHIJKLMNOPQRSTUVWXYZ".casefold() in response and "0123456789" in response:
                return True, "Chargen"
            else:
                return False, None
    except (socket.timeout, socket.error) as e:
        return False, None

def identify_service(host, port):
    # HTTP 연결 시도
    http_check, http_msg = check_http_service(host, port)
    if http_check:
        return f"HTTP Service {http_msg}"

    tcp_check, tcp_msg = check_tcp_service(host, port)
    if tcp_check:
        return f"{tcp_msg}"
    
    request_check, request_msg = send_request(host, port)
    if request_check:
        return f"{request_msg}"
    
    ssl_check, ssl_msg = check_ssl.ssl_client(host, port)
    if ssl_check:
        if "Dovecot".casefold() in ssl_msg:
            return f"SSL-Dovecot"
        
        return "SSL"
    
    dns_check = check_dns.detect_dns_service(host, port)
    if dns_check:
        return "DNS"
    
    echo_check = check_echo.detect_echo_service(host, port)
    if echo_check:
        return "Echo"
    
    time_check, timestamp = check_time.check_time_protocol(host, port)
    if time_check:
        if port == 37:
            return f"Time - {timestamp}"
        else:
            return f"Time? - {timestamp}"
        
    daytime_check, daytime_info = check_daytime.check_daytime_service(host, port)
    if daytime_check:
        return f"Daytime - {daytime_info}"
    
    if cfs.is_ftp_service(host, port):
        return "FTP"
    
    asn1_check, asn1_msg = get_ASN1.recv_ASN1_packet(host, port)
    if asn1_check:
        return asn1_msg

    if port == 9 and tcp_msg == False:
        return f"Discard?"

    return "Unknown Service"