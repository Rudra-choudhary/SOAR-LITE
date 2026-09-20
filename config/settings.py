import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Threat Score Weights (total = 1.0)
WEIGHTS = {
    "virustotal": 0.40,
    "abuseipdb": 0.30,
    "shodan": 0.15,
    "alienvault": 0.15,
}

# Severity Thresholds
SEVERITY_LEVELS = {
    "CRITICAL": 80,
    "HIGH": 60,
    "MEDIUM": 40,
    "LOW": 20,
    "CLEAN": 0,
}

# Supported IOC Types
IOC_TYPES = ["ip", "domain", "url", "hash"]
