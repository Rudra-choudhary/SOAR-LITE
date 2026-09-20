import re
import hashlib
import socket

def resolve_domain_to_ip(domain: str) -> str:
    """Resolve a domain name to its primary IPv4 address."""
    try:
        # Strip protocol or path if present
        clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(clean_domain)
        return ip
    except socket.gaierror:
        return None


def identify_ioc_type(ioc: str) -> str:
    """
    Identify the type of Indicator of Compromise.
    Returns: 'ip', 'domain', 'url', 'hash', or 'unknown'
    """
    ioc = ioc.strip()

    # Check if it's a URL
    if re.match(r'^https?://', ioc):
        return "url"

    # Check if it's an IPv4 address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        octets = ioc.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            return "ip"

    # Check if it's a hash (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', ioc):   # MD5
        return "hash"
    if re.match(r'^[a-fA-F0-9]{40}$', ioc):   # SHA1
        return "hash"
    if re.match(r'^[a-fA-F0-9]{64}$', ioc):   # SHA256
        return "hash"

    # Check if it's a domain
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', ioc):
        return "domain"

    return "unknown"


def validate_ioc(ioc: str) -> dict:
    """Validate and return IOC info"""
    ioc_type = identify_ioc_type(ioc)
    return {
        "value": ioc.strip(),
        "type": ioc_type,
        "valid": ioc_type != "unknown"
    }


# Quick test
if __name__ == "__main__":
    test_cases = [
        "8.8.8.8",
        "google.com",
        "https://malware.com/payload",
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5
        "random_garbage!!!"
    ]
    for t in test_cases:
        result = validate_ioc(t)
        print(f"{t:50s} -> {result['type']:10s} (valid: {result['valid']})")
