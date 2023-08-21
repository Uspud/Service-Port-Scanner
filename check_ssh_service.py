import paramiko

def can_connect_ssh(host, port):
    client = paramiko.SSHClient()
    # client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(host, port, timeout=2)
        return True
    except (paramiko.AuthenticationException, paramiko.SSHException):
        # AuthenticationException means we reached an SSH server and it's asking for credentials.
        # SSHException could also indicate a connection, but we should be careful as it can also indicate other SSH errors.
        return True
    except Exception as e:
        # Other exceptions (like socket.timeout) indicate we didn't reach an SSH server.
        return False
    finally:
        client.close()