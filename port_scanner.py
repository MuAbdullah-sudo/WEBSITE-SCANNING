import socket

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

def scan_ports(domain):
    open_ports = []

    for port in COMMON_PORTS:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((domain, port))
            open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports