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

import os
import requests
import logging


def enrich_ip(ip):
    debug_mode = os.getenv("DEBUG_MODE", "false").lower() == "true"
    if debug_mode:
        enrichment = {
            "abuse_score": 75,
            "country": "RU",
            "source": "mock",
            "total_reports": 30,
            "last_reported_at": "2024-12-01T11:22:00+00:00",
            "usage_type": "Data Center/Web Hosting/Transit",
            "asn": 9009
        }
        logging.info(f"[MOCK ENRICH] IP {ip} => {enrichment}")
        return enrichment

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logging.warning("AbuseIPDB API key not found. Using fallback.")
        return {
            "abuse_score": 0,
            "country": "unknown",
            "source": "fallback"
        }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=5
        )

        logging.info(f"AbuseIPDB response status: {response.status_code}")

        data = response.json().get("data", {})
        enrichment = {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "unknown"),
            "source": "abuseipdb",
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "usage_type": data.get("usageType"),
            "asn": data.get("asn")
        }
        logging.info(f"[ENRICH] IP {ip} => {enrichment}")
        return enrichment

    except Exception as e:
        logging.error(f"Error querying AbuseIPDB: {e}")
        return {
            "abuse_score": 0,
            "country": "unknown",
            "source": "error"
        }