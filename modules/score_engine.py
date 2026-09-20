from config.settings import WEIGHTS, SEVERITY_LEVELS
from datetime import datetime


def calculate_weighted_score(results: list) -> dict:
    """
    Calculate a weighted threat score from all source results.
    Adjusts weights dynamically if a source was skipped.
    """
    active_sources = {}
    skipped_sources = []

    for result in results:
        source_key = result["source"].lower().replace(" ", "")

        # Map source names to weight keys
        weight_map = {
            "virustotal": "virustotal",
            "abuseipdb": "abuseipdb",
            "shodan": "shodan",
            "alienvaultotx": "alienvault"
        }

        mapped_key = weight_map.get(source_key, source_key)

        if result.get("skipped") or result.get("error"):
            skipped_sources.append(mapped_key)
        else:
            active_sources[mapped_key] = result.get("score", 0)

    # Recalculate weights for active sources only
    active_weights = {k: v for k, v in WEIGHTS.items() if k in active_sources}
    total_active_weight = sum(active_weights.values())

    if total_active_weight == 0:
        return {
            "final_score": 0,
            "severity": "UNKNOWN",
            "breakdown": {},
            "skipped": skipped_sources,
            "error": "No threat intelligence sources returned data"
        }

    # Normalize weights
    normalized_weights = {k: v / total_active_weight for k, v in active_weights.items()}

    # Calculate weighted score
    weighted_score = sum(
        active_sources[source] * normalized_weights[source]
        for source in active_sources
    )

    final_score = round(weighted_score, 2)

    # Determine severity
    severity = "CLEAN"
    for level, threshold in sorted(SEVERITY_LEVELS.items(), key=lambda x: x[1], reverse=True):
        if final_score >= threshold:
            severity = level
            break

    # Build breakdown
    breakdown = {}
    for source, score in active_sources.items():
        breakdown[source] = {
            "raw_score": score,
            "weight": round(normalized_weights[source], 2),
            "weighted_contribution": round(score * normalized_weights[source], 2)
        }

    return {
        "final_score": final_score,
        "severity": severity,
        "breakdown": breakdown,
        "skipped_sources": skipped_sources,
        "timestamp": datetime.utcnow().isoformat(),
        "error": None
    }


def get_severity_color(severity: str) -> str:
    """Return color codes for terminal output"""
    colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "green",
        "CLEAN": "bright_green",
        "UNKNOWN": "grey50"
    }
    return colors.get(severity, "white")


def get_recommendation(severity: str) -> str:
    """Return action recommendations based on severity"""
    recommendations = {
        "CRITICAL": "🚨 IMMEDIATE ACTION REQUIRED: Block this IOC at firewall/proxy. "
                    "Initiate incident response. Search SIEM for all historical connections.",
        "HIGH": "⚠️ HIGH PRIORITY: Add to blocklist. Investigate any internal hosts "
                "that communicated with this IOC in the last 30 days.",
        "MEDIUM": "🔶 MONITOR: Add to watchlist. Enable enhanced logging for any "
                  "connections to this IOC. Review in 24 hours.",
        "LOW": "🔵 LOW RISK: Likely benign but log for baseline. No immediate action needed.",
        "CLEAN": "✅ NO THREAT DETECTED: This IOC appears clean across all sources.",
        "UNKNOWN": "❓ INSUFFICIENT DATA: Manual analysis recommended."
    }
    return recommendations.get(severity, "Manual review recommended.")
