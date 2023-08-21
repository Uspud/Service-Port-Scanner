import smtplib
import socket

def can_connect_smtp(host, port):   # 주어진 호스트와 포트로 SMTP 서버에 연결할 수 있는지 여부 반환
    server = None
    try:
        server = smtplib.SMTP(host, port, timeout=2)
        server.ehlo()
        return True
    except Exception as e:
        return False