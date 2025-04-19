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
from core.services.enrichment import virustotal
from core.services.enrichment.abuseipdb import enrich_ip as abuseipdb_enrich

logger = logging.getLogger(__name__)


def enrich_ioc(ioc_type: str, ioc_value: str) -> dict:
    result = {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "sources": {},
        "risk_score": 0
    }

    try:
        # Enrichment with AbuseIPDB (only if it is IP)
        if ioc_type == "ip":
            abuse_data = abuseipdb_enrich(ioc_value)
            result["sources"]["abuseipdb"] = abuse_data

        # VirusTotal Enrichment
        if ioc_type == "ip":
            vt_data = virustotal.get_ip_report(ioc_value)
        elif ioc_type == "domain":
            vt_data = virustotal.get_domain_report(ioc_value)
        elif ioc_type == "hash":
            vt_data = virustotal.get_file_hash_report(ioc_value)
        elif ioc_type == "url":
            vt_data = virustotal.get_url_report(ioc_value)
        else:
            vt_data = {"error": f"Unsupported IOC type: {ioc_type}"}

        result["sources"]["virustotal"] = vt_data

        # Cálculo de risco baseado em enriquecimentos
        result["risk_score"] = calculate_combined_risk(result["sources"], ioc_type)

    except Exception as e:
        logger.exception("Failed to enrich IOC")
        result["error"] = str(e)

    return result


def calculate_combined_risk(sources: dict, ioc_type: str) -> int:
    score = 0

    # AbuseIPDB: reputation + number of reports
    if "abuseipdb" in sources and isinstance(sources["abuseipdb"], dict):
        abuse_data = sources["abuseipdb"]
        if "abuseConfidenceScore" in abuse_data:
            score += int(abuse_data["abuseConfidenceScore"])  # 0-100

    # VirusTotal: number of engines that detect
    if "virustotal" in sources and isinstance(sources["virustotal"], dict):
        vt_data = sources["virustotal"]
        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # Each 'malicious' engine is worth 5 points, 'suspicious' is worth 2
        score += (malicious * 5) + (suspicious * 2)

    # Limits between 0 and 100
    return min(score, 100)