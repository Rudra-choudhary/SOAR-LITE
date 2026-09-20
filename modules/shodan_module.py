import requests
from config.settings import SHODAN_API_KEY


def query(ioc: str, ioc_type: str) -> dict:
    """Query Shodan - supports IP addresses"""
    if ioc_type != "ip":
        return {
            "source": "Shodan",
            "score": 0,
            "error": "Shodan module currently supports IP lookups only",
            "skipped": True
        }

    url = f"https://api.shodan.io/shodan/host/{ioc}?key={SHODAN_API_KEY}"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            open_ports = data.get("ports", [])
            vulns = data.get("vulns", [])

            # Risk score based on exposed services and vulnerabilities
            risk_score = min(len(open_ports) * 5 + len(vulns) * 15, 100)

            return {
                "source": "Shodan",
                "ioc_type": "ip",
                "open_ports": open_ports,
                "num_open_ports": len(open_ports),
                "vulns": vulns,
                "num_vulns": len(vulns),
                "os": data.get("os", "N/A"),
                "organization": data.get("org", "N/A"),
                "isp": data.get("isp", "N/A"),
                "hostnames": data.get("hostnames", []),
                "score": risk_score,
                "error": None
            }
        elif response.status_code == 404:
            return {"source": "Shodan", "score": 0, "error": "IP not found in Shodan"}
        else:
            return {"source": "Shodan", "score": 0, "error": f"HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"source": "Shodan", "score": 0, "error": str(e)}
