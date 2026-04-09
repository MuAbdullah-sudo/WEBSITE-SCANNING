import requests

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test"
]

def find_subdomains(domain):
    found = []

    for sub in COMMON_SUBDOMAINS:
        url = f"http://{sub}.{domain}"
        try:
            requests.get(url, timeout=2)
            found.append(url)
        except:
            pass

    return found