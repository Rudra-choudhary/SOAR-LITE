import requests
from config.settings import ABUSEIPDB_API_KEY
from utils.input_parser import resolve_domain_to_ip


def query(ioc: str, ioc_type: str) -> dict:
    """Query AbuseIPDB - supports IP, and resolves Domains to IP automatically"""
    target_ip = ioc

    if ioc_type == "domain":
        target_ip = resolve_domain_to_ip(ioc)
        if not target_ip:
            return {
                "source": "AbuseIPDB",
                "score": 0,
                "error": f"Could not resolve domain '{ioc}' to an IP address",
                "skipped": True
            }
    elif ioc_type != "ip":
        return {
            "source": "AbuseIPDB",
            "score": 0,
            "error": "AbuseIPDB only supports IP addresses and Domains",
            "skipped": True
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": target_ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "source": "AbuseIPDB",
                "ioc_type": ioc_type,
                "resolved_ip": target_ip if ioc_type == "domain" else None,
                "abuse_confidence_score": data.get("abuseConfidencePercentage", 0),
                "score": data.get("abuseConfidencePercentage", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "domain": data.get("domain", "N/A"),
                "usage_type": data.get("usageType", "N/A"),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "last_reported": data.get("lastReportedAt", "Never"),
                "error": None
            }
        else:
            return {"source": "AbuseIPDB", "score": 0, "error": f"HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"source": "AbuseIPDB", "score": 0, "error": str(e)}
