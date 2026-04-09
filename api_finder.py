import requests

COMMON_ENDPOINTS = [
    "/api", "/api/v1", "/api/login", "/graphql", "/auth"
]

def find_apis(url):
    found = []

    for endpoint in COMMON_ENDPOINTS:
        try:
            full_url = url + endpoint
            r = requests.get(full_url, timeout=2)
            if r.status_code < 400:
                found.append(full_url)
        except:
            pass

    return found