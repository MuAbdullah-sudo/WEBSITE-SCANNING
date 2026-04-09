import requests

def check_vulnerabilities(url):
    results = {}

    try:
        # Check if HTTP (not HTTPS)
        if url.startswith("http://"):
            results["insecure_http"] = True
        else:
            results["insecure_http"] = False

        # Check headers
        response = requests.get(url)
        headers = response.headers

        if "X-Frame-Options" not in headers:
            results["clickjacking_risk"] = True
        else:
            results["clickjacking_risk"] = False

        if "Content-Security-Policy" not in headers:
            results["xss_risk"] = True
        else:
            results["xss_risk"] = False

        return results

    except Exception as e:
        return {"error": str(e)}