import requests

def detect_technology(url):
    try:
        response = requests.get(url)
        headers = response.headers
        html = response.text.lower()

        tech = []

        # Header-based detection
        server = headers.get("Server")
        if server:
            tech.append(server)

        # Basic fingerprinting
        if "wp-content" in html:
            tech.append("WordPress")

        if "react" in html:
            tech.append("React")

        if "angular" in html:
            tech.append("Angular")

        if "vue" in html:
            tech.append("Vue.js")

        return list(set(tech))

    except Exception as e:
        return {"error": str(e)}