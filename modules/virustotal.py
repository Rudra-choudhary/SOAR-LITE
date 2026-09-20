"""
VirusTotal API v3 Integration Module
Supports: IPv4, Domain, URL, File Hash (MD5/SHA1/SHA256)
API Docs: https://docs.virustotal.com/reference/overview
"""

import base64
import requests
from datetime import datetime, timezone
from config.settings import VIRUSTOTAL_API_KEY


def _format_epoch(epoch: int) -> str:
    """Convert Unix epoch timestamp to human-readable UTC string."""
    if not epoch:
        return "N/A"
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError, TypeError):
        return "N/A"


def _build_base_result(ioc_type: str, **kwargs) -> dict:
    """Build a standardized result dictionary."""
    return {
        "source": "VirusTotal",
        "ioc_type": ioc_type,
        **kwargs
    }


def query_ip(ip: str) -> dict:
    """Query VirusTotal for IP address reputation."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = sum(stats.values())

            score = round(((malicious + suspicious) / total) * 100, 2) if total > 0 else 0

            return _build_base_result(
                ioc_type="ip",
                malicious_detections=malicious,
                suspicious_detections=suspicious,
                harmless_detections=harmless,
                undetected=undetected,
                total_engines=total,
                detection_ratio=f"{malicious}/{total}",
                score=score,
                country=data.get("country", "N/A"),
                continent=data.get("continent", "N/A"),
                as_number=data.get("asn", "N/A"),
                as_owner=data.get("as_owner", "N/A"),
                network=data.get("network", "N/A"),
                reputation=data.get("reputation", 0),
                whois_date=_format_epoch(data.get("whois_date")),
                last_analysis_date=_format_epoch(data.get("last_analysis_date")),
                error=None
            )

        elif response.status_code == 404:
            return _build_base_result("ip", score=0, error="IP not found in VirusTotal database")

        elif response.status_code == 429:
            return _build_base_result("ip", score=0, error="API rate limit exceeded (429)")

        elif response.status_code == 401:
            return _build_base_result("ip", score=0, error="Invalid API key (401)")

        else:
            return _build_base_result("ip", score=0, error=f"HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        return _build_base_result("ip", score=0, error="Request timed out")
    except requests.exceptions.ConnectionError:
        return _build_base_result("ip", score=0, error="Connection failed")
    except requests.exceptions.RequestException as e:
        return _build_base_result("ip", score=0, error=str(e))


def query_domain(domain: str) -> dict:
    """Query VirusTotal for domain reputation."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = sum(stats.values())

            score = round(((malicious + suspicious) / total) * 100, 2) if total > 0 else 0

            # Extract popular threat categories if any
            categories = data.get("categories", {})
            top_categories = list(categories.values())[:3] if categories else ["None"]

            return _build_base_result(
                ioc_type="domain",
                malicious_detections=malicious,
                suspicious_detections=suspicious,
                harmless_detections=harmless,
                undetected=undetected,
                total_engines=total,
                detection_ratio=f"{malicious}/{total}",
                score=score,
                reputation=data.get("reputation", 0),
                registrar=data.get("registrar", "N/A"),
                creation_date=_format_epoch(data.get("creation_date")),
                last_update_date=_format_epoch(data.get("last_update_date")),
                last_analysis_date=_format_epoch(data.get("last_analysis_date")),
                expiration_date=_format_epoch(data.get("expiration_date")),
                whois_date=_format_epoch(data.get("whois_date")),
                categories=", ".join(top_categories),
                tld=data.get("tld", "N/A"),
                error=None
            )

        elif response.status_code == 404:
            return _build_base_result("domain", score=0, error="Domain not found in VirusTotal database")

        elif response.status_code == 429:
            return _build_base_result("domain", score=0, error="API rate limit exceeded (429)")

        elif response.status_code == 401:
            return _build_base_result("domain", score=0, error="Invalid API key (401)")

        else:
            return _build_base_result("domain", score=0, error=f"HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        return _build_base_result("domain", score=0, error="Request timed out")
    except requests.exceptions.ConnectionError:
        return _build_base_result("domain", score=0, error="Connection failed")
    except requests.exceptions.RequestException as e:
        return _build_base_result("domain", score=0, error=str(e))


def query_url(target_url: str) -> dict:
    """
    Query VirusTotal for URL reputation.
    VT API v3 requires the URL to be base64-encoded (without padding) as the ID.
    """
    # VirusTotal URL ID = base64(url) with trailing '=' stripped
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = sum(stats.values())

            score = round(((malicious + suspicious) / total) * 100, 2) if total > 0 else 0

            return _build_base_result(
                ioc_type="url",
                malicious_detections=malicious,
                suspicious_detections=suspicious,
                harmless_detections=harmless,
                undetected=undetected,
                total_engines=total,
                detection_ratio=f"{malicious}/{total}",
                score=score,
                url=data.get("url", target_url),
                final_url=data.get("last_final_url", "N/A"),
                title=data.get("title", "N/A"),
                reputation=data.get("reputation", 0),
                last_analysis_date=_format_epoch(data.get("last_analysis_date")),
                first_submission_date=_format_epoch(data.get("first_submission_date")),
                last_submission_date=_format_epoch(data.get("last_submission_date")),
                times_submitted=data.get("times_submitted", "N/A"),
                error=None
            )

        elif response.status_code == 404:
            return _build_base_result("url", score=0, error="URL not found in VirusTotal database (never scanned)")

        elif response.status_code == 429:
            return _build_base_result("url", score=0, error="API rate limit exceeded (429)")

        elif response.status_code == 401:
            return _build_base_result("url", score=0, error="Invalid API key (401)")

        else:
            return _build_base_result("url", score=0, error=f"HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        return _build_base_result("url", score=0, error="Request timed out")
    except requests.exceptions.ConnectionError:
        return _build_base_result("url", score=0, error="Connection failed")
    except requests.exceptions.RequestException as e:
        return _build_base_result("url", score=0, error=str(e))


def query_hash(file_hash: str) -> dict:
    """Query VirusTotal for file hash reputation (MD5, SHA-1, SHA-256)."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = sum(stats.values())

            score = round(((malicious + suspicious) / total) * 100, 2) if total > 0 else 0

            # Extract hash values
            hashes = {
                "md5": data.get("md5", "N/A"),
                "sha1": data.get("sha1", "N/A"),
                "sha256": data.get("sha256", "N/A"),
            }

            # Extract sandbox/behavior tags
            tags = data.get("tags", [])
            popular_threat_classification = data.get("popular_threat_classification", {})
            suggested_label = popular_threat_classification.get("suggested_threat_label", "N/A")

            return _build_base_result(
                ioc_type="hash",
                malicious_detections=malicious,
                suspicious_detections=suspicious,
                harmless_detections=harmless,
                undetected=undetected,
                total_engines=total,
                detection_ratio=f"{malicious}/{total}",
                score=score,
                file_name=data.get("meaningful_name", data.get("names", ["N/A"])[0] if data.get("names") else "N/A"),
                file_type=data.get("type_description", "N/A"),
                file_size=data.get("size", "N/A"),
                type_tag=data.get("type_tag", "N/A"),
                suggested_threat_label=suggested_label,
                tags=", ".join(tags[:10]) if tags else "None",
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                sha256=hashes["sha256"],
                first_submission_date=_format_epoch(data.get("first_submission_date")),
                last_analysis_date=_format_epoch(data.get("last_analysis_date")),
                times_submitted=data.get("times_submitted", "N/A"),
                error=None
            )

        elif response.status_code == 404:
            return _build_base_result("hash", score=0, error="Hash not found in VirusTotal database")

        elif response.status_code == 429:
            return _build_base_result("hash", score=0, error="API rate limit exceeded (429)")

        elif response.status_code == 401:
            return _build_base_result("hash", score=0, error="Invalid API key (401)")

        else:
            return _build_base_result("hash", score=0, error=f"HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        return _build_base_result("hash", score=0, error="Request timed out")
    except requests.exceptions.ConnectionError:
        return _build_base_result("hash", score=0, error="Connection failed")
    except requests.exceptions.RequestException as e:
        return _build_base_result("hash", score=0, error=str(e))


def query(ioc: str, ioc_type: str) -> dict:
    """
    Main dispatcher - routes to the correct query function based on IOC type.
    """
    if not VIRUSTOTAL_API_KEY:
        return _build_base_result(ioc_type, score=0, error="VirusTotal API key not configured in .env")

    dispatch = {
        "ip": query_ip,
        "domain": query_domain,
        "url": query_url,
        "hash": query_hash,
    }

    handler = dispatch.get(ioc_type)
    if handler:
        return handler(ioc)
    else:
        return _build_base_result(ioc_type, score=0, error=f"Unsupported IOC type: {ioc_type}")
