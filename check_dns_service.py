import dns.query
import dns.resolver
import dns.exception
import dns.message
import dns.rcode
import dns.rdatatype

def check_dns_service_1_UDP(host, port):
    try:
        # Test if the given host and port respond to DNS queries
        dns.query.udp(dns.message.make_query('google.com', 'A'), host, port=port, timeout=2)
        return True
    except dns.exception.Timeout:
        return False
    except Exception as e:
        return False
    
def check_dns_service_1_tcp(host, port):
    try:
        dns.query.tcp(dns.message.make_query('google.com', 'A'), host, port=port, timeout=2)
        return True
    except dns.exception.Timeout:
        return False
    except Exception as e:
        return False

def check_dns_service_2(host, port):
    try:
        # DNS 질의 생성
        query = dns.message.make_query('.', dns.rdatatype.NS)

        # 호스트와 포트에서 존재하는 DNS 서버에 질의를 전송합니다.
        response = dns.query.udp(query, host, port=port, timeout=5)

        # 요청된 질의에 대한 올바른 응답을 가진 경우 DNS 서비스로 간주합니다.
        if response.rcode() == dns.rcode.NOERROR:
            return True
    except Exception as e:
        return False

    return False

    
def detect_dns_service(host, port):
    dns_flag = False
    if check_dns_service_1_UDP(host, port):
        dns_flag = True
    elif check_dns_service_1_tcp(host, port):
        dns_flag = True
    elif check_dns_service_2(host, port):
        dns_flag = True

    return dns_flag