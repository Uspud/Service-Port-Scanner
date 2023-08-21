from ftplib import *

def is_ftp_service(host, port):
    try:
        # FTP 서버 접속 시도
        with FTP() as ftp:
            ftp.connect(host=host, port=port, timeout=5)
            
            # 'user' 명령어를 사용하여 응답 확인
            response = ftp.sendcmd('USER test')
            # 응답 출력 (옵션)
            if '331' in response:
                return True
    except Exception as e:
        return False
