import requests
import ssl
import socket
from urllib.parse import urlparse
import whois

# ---------------- SSL CHECK ----------------
def check_ssl(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        return {
            "issuer": dict(x[0] for x in cert['issuer']),
            "valid_from": cert['notBefore'],
            "valid_to": cert['notAfter']
        }

    except Exception as e:
        return {"error": str(e)}

# ---------------- HEADERS CHECK ----------------
def check_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers

        return {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy")
        }

    except Exception as e:
        return {"error": str(e)}

# ---------------- WHOIS CHECK ----------------
def check_whois(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        domain_info = whois.whois(domain)

        return {
            "domain_name": str(domain_info.domain_name),
            "registrar": str(domain_info.registrar),
            "creation_date": str(domain_info.creation_date),
            "expiration_date": str(domain_info.expiration_date)
        }

    except Exception as e:
        return {"error": str(e)}
    

   