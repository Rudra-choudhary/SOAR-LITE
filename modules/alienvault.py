"""
AlienVault OTX API Integration Module
Supports: IPv4, Domain, File Hash, URL
API Docs: https://otx.alienvault.com/api
"""

import requests
from config.settings import ALIENVAULT_API_KEY


def query(ioc: str, ioc_type: str) -> dict:
    """Query AlienVault OTX for threat intelligence pulses."""

    type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "hash": "file",
        "url": "url"
    }

    otx_type = type_map.get(ioc_type)
    if not otx_type:
        return {
            "source": "AlienVault OTX",
            "score": 0,
            "error": f"Unsupported IOC type: {ioc_type}",
            "skipped": True
        }

    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general"

    # Configure headers
    headers = {}
    if ALIENVAULT_API_KEY:
        headers["X-OTX-API-KEY"] = ALIENVAULT_API_KEY

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)

            # Calculate threat score based on pulse references
            if pulse_count == 0:
                score = 0
            elif pulse_count <= 3:
                score = 30
            elif pulse_count <= 10:
                score = 60
            else:
                score = 90

            # Extract pulse names
            pulses = pulse_info.get("pulses", [])
            pulse_names = [p.get("name", "Unknown Threat Pulse") for p in pulses[:5]]

            # Country extraction
            country = data.get("country_name") or data.get("country_code") or "N/A"

            return {
                "source": "AlienVault OTX",
                "ioc_type": ioc_type,
                "pulse_count": pulse_count,
                "score": score,
                "pulse_names": ", ".join(pulse_names) if pulse_names else "None",
                "country": country,
                "error": None
            }

        elif response.status_code == 404:
            return {"source": "AlienVault OTX", "score": 0, "error": "Indicator not found in OTX database"}

        elif response.status_code == 403:
            return {"source": "AlienVault OTX", "score": 0, "error": "Invalid AlienVault API Key (403 Forbidden)"}

        else:
            return {"source": "AlienVault OTX", "score": 0, "error": f"HTTP {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"source": "AlienVault OTX", "score": 0, "error": "AlienVault request timed out"}
    except requests.exceptions.RequestException as e:
        return {"source": "AlienVault OTX", "score": 0, "error": str(e)}
