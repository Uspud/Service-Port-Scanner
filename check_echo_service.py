import socket
import os

def test_echo_service(server_ip, server_port, byte_size):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))
        client_socket.settimeout(5)

        random_data = os.urandom(byte_size)
        client_socket.send(random_data)

        received_data = client_socket.recv(byte_size)

        client_socket.close()
        return random_data == received_data
    except Exception as e:
        return False


def detect_echo_service(host, port):
    byte_sizes = [256, 512, 1024]

    for size in byte_sizes:
        if not test_echo_service(host, port, size):
            return False

    return True