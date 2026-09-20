import requests
from config.settings import ALIENVAULT_API_KEY


def query(ioc: str, ioc_type: str) -> dict:
    """Query AlienVault OTX for threat intelligence"""
    type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "hash": "file",
        "url": "url"
    }

    otx_type = type_map.get(ioc_type)
    if not otx_type:
        return {"source": "AlienVault OTX", "score": 0, "error": "Unsupported IOC type"}

    section = "general"
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/{section}"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            # Score based on number of threat reports (pulses)
            if pulse_count == 0:
                score = 0
            elif pulse_count <= 3:
                score = 30
            elif pulse_count <= 10:
                score = 60
            else:
                score = 90

            pulses = data.get("pulse_info", {}).get("pulses", [])
            pulse_names = [p.get("name", "Unknown") for p in pulses[:5]]

            return {
                "source": "AlienVault OTX",
                "ioc_type": ioc_type,
                "pulse_count": pulse_count,
                "score": score,
                "pulse_names": pulse_names,
                "country": data.get("country_code", "N/A"),
                "error": None
            }
        else:
            return {"source": "AlienVault OTX", "score": 0, "error": f"HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"source": "AlienVault OTX", "score": 0, "error": str(e)}
