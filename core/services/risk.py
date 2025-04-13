#!/usr/bin/env python
# SOAR Lite Threat Intel Automation
#
# Copyright 2025 Renato Kopke (@renatokopke)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from datetime import datetime, timezone
import json
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RISK_COUNTRY_FILE = os.path.join(BASE_DIR, "data", "high_abuse_countries.json")

high_risk_countries = []
if os.path.exists(RISK_COUNTRY_FILE):
    try:
        with open(RISK_COUNTRY_FILE, "r") as f:
            high_risk_countries = json.load(f)
    except Exception as e:
        logging.warning(f"Could not load high-risk countries from file: {e}")
        high_risk_countries = []
else:
    logging.warning(f"High-risk country file not found: {RISK_COUNTRY_FILE}")


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
        except Exception as e:
            logging.warning(f"Invalid last_reported_at: {last_seen} ({e})")

    if enrichment.get("usage_type") in [
        "Data Center/Web Hosting/Transit",
        "Content Delivery Network",
        "Fixed Line ISP"
    ]:
        score += 10

    if enrichment.get("country") in high_risk_countries:
        score += 5

    logging.debug(f"Calculated risk score: {score} for event_type={event_type}")

    return min(score, 100)