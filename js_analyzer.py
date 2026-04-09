import requests
import re

def analyze_js(url):
    results = {
        "js_files": [],
        "suspicious_keywords": []
    }

    try:
        response = requests.get(url)
        html = response.text

        # Find JS files
        scripts = re.findall(r'<script.*?src="(.*?)"', html)
        results["js_files"] = scripts

        # Check suspicious patterns
        keywords = ["eval(", "document.cookie", "localStorage", "innerHTML"]

        for word in keywords:
            if word in html:
                results["suspicious_keywords"].append(word)

        return results

    except Exception as e:
        return {"error": str(e)}

        