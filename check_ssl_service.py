import socket
import ssl

def create_connection(host, port, timeout=3):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout)  # 타임아웃 설정
    try:
        client.connect((host, port))
        return client
    except socket.error as e:
        return None

def ssl_check1(host, port):
    protocols = [
        ssl.PROTOCOL_TLSv1_2,
        ssl.PROTOCOL_TLSv1_1,
        ssl.PROTOCOL_TLSv1,
        ssl.PROTOCOL_SSLv23,
        ssl.PROTOCOL_TLS_CLIENT
    ]

    for protocol in protocols:
        client = create_connection(host, port)
        if client is None:
            return False, None

        context = ssl.SSLContext(protocol)
        try:
            secure_client = context.wrap_socket(client, server_hostname=host)

            message = "Hello from the client!"
            secure_client.sendall(message.encode('utf-8'))

            response = secure_client.recv(1024).decode('utf-8', errors='ignore').casefold()

            secure_client.close()
            return True, response

        except Exception:
            client.close()
            return False, None

def ssl_check2(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try: 
        with context.wrap_socket(socket.socket(), server_hostname = ip) as s:
            s.connect(host, port)
            s.getpeercert()
            return True
    except Exception:
        return False
    
def ssl_client(host, port):
    flag = False
    recv = ''

    var1, var2 = ssl_check1(host, port)
    if var1:
        flag = var1
        recv = var2

    if ssl_check2(host, port):
        flag = True

    return flag, recv