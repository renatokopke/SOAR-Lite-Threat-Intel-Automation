from datetime import datetime, timezone
import json
import os

RISK_COUNTRY_FILE = "data/high_abuse_countries.json"
high_risk_countries = []
if os.path.exists(RISK_COUNTRY_FILE):
    try:
        with open(RISK_COUNTRY_FILE, "r") as f:
            high_risk_countries = json.load(f)
    except Exception:
        high_risk_countries = []


def calculate_risk_score(enrichment, event_type):
    score = enrichment.get("abuse_score", 0)

    if event_type == "port_scan":
        score += 10
    elif event_type == "suspicious_login":
        score += 20
    elif event_type == "malware_traffic":
        score += 30
    elif event_type == "brute_force":
        score += 25
    elif event_type == "data_exfiltration":
        score += 40

    total_reports = enrichment.get("total_reports", 0)
    if total_reports > 50:
        score += 15
    elif total_reports > 20:
        score += 10
    elif total_reports > 5:
        score += 5

    last_seen = enrichment.get("last_reported_at")
    if last_seen:
        try:
            last_seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            days_since = (datetime.now(timezone.utc) - last_seen_dt).days
            if days_since <= 3:
                score += 10
            elif days_since <= 7:
                score += 5
        except Exception:
            pass

    if enrichment.get("usage_type") in [
        "Data Center/Web Hosting/Transit",
        "Content Delivery Network",
        "Fixed Line ISP"
    ]:
        score += 10

    if enrichment.get("country") in high_risk_countries:
        score += 5

    return min(score, 100)