from scapy.all import *

def recv_ASN1_packet(ip, port):
    bindRequest = '\x30\x25\x02\x01\x01\x60\x20\x02\x01\x03\x04\x13\x63\x6e\x3d\x44\x69\x72\x65\x63\x74\x6f\x72\x79\x20\x4d\x61\x6e\x61\x67\x65\x72\x80\x08\x70\x61\x73\x73\x77\x6f\x72\x64'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    
    try:
        s.connect((ip, port))
        s.send(bindRequest.encode('latin-1'))
        data = s.recv(1024)
        s.close()

        if b"krbtgt" in data:
            return True, "Kerberos"

        if b'1.3.6.1.4.1.1466.20036' in data:
            return True, "LDAP"
        
        else:
            return False, None
        
    except Exception as e:
        return False, None
