import http.client

def extract_server_headers(ip, port):
    try:
        connection = http.client.HTTPConnection(ip, port, timeout=3)
        connection.request("HEAD", "/")
        response = connection.getresponse()
        server_header = response.getheader("Server")
        return server_header
    except Exception as e:
        return None
    finally:
        connection.close()

def get_server_header(host, port):
    server_header = extract_server_headers(host, port)
    if server_header:
        return server_header
    else:
        return "Unknown"