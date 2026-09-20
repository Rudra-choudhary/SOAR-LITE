import requests
import json
from config.settings import DISCORD_WEBHOOK_URL


def send_discord_alert(ioc: str, ioc_type: str, score_data: dict) -> bool:
    """Send a formatted alert to Discord via webhook"""
    if not DISCORD_WEBHOOK_URL:
        print("[!] Discord webhook URL not configured. Skipping notification.")
        return False

    severity = score_data["severity"]
    score = score_data["final_score"]

    # Color codes for Discord embeds
    color_map = {
        "CRITICAL": 0xFF0000,  # Red
        "HIGH": 0xFF8C00,      # Dark Orange
        "MEDIUM": 0xFFD700,    # Gold
        "LOW": 0x32CD32,       # Lime Green
        "CLEAN": 0x00FF00,     # Green
        "UNKNOWN": 0x808080    # Gray
    }

    # Build breakdown string
    breakdown_str = ""
    for source, details in score_data.get("breakdown", {}).items():
        breakdown_str += f"**{source.title()}**: {details['raw_score']}/100 (weight: {details['weight']})\n"

    if score_data.get("skipped_sources"):
        breakdown_str += f"\n*Skipped:* {', '.join(score_data['skipped_sources'])}"

    from modules.score_engine import get_recommendation
    recommendation = get_recommendation(severity)

    embed = {
        "embeds": [{
            "title": f"🔍 Threat Intel Alert - {severity}",
            "color": color_map.get(severity, 0xFFFFFF),
            "fields": [
                {"name": "IOC", "value": f"`{ioc}`", "inline": True},
                {"name": "Type", "value": ioc_type.upper(), "inline": True},
                {"name": "Threat Score", "value": f"**{score}/100**", "inline": True},
                {"name": "Severity", "value": severity, "inline": True},
                {"name": "Score Breakdown", "value": breakdown_str, "inline": False},
                {"name": "Recommendation", "value": recommendation, "inline": False},
            ],
            "footer": {"text": "SOAR-Lite Threat Intel Tool"},
            "timestamp": score_data.get("timestamp", "")
        }]
    }

    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            data=json.dumps(embed),
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.status_code == 204
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to send Discord alert: {e}")
        return False
