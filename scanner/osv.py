import requests


OSV_API = "https://api.osv.dev/v1/query"

# check for vulnerabilities using OSV API
def check_vulnerability(package_name, version):
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "npm"
        },
        "version": version
    }

    try:
        response = requests.post(OSV_API, json=payload, timeout=10)
        data = response.json()

        vulns = data.get("vulns", [])

        return vulns

    except Exception as e:
        print("OSV Error:", e)
        return []
