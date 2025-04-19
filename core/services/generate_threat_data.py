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
import json
from collections import Counter, defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RESULTS_PATH = os.path.join(BASE_DIR, "output", "results.json")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "threat_data.json")


def generate_threat_data():
    """
    Parses results.json and returns summarized metrics for the Threat Intelligence Overview dashboard.
    Also saves the output to data/threat_data.json for optional offline usage.
    """
    if not os.path.exists(RESULTS_PATH):
        print("[!] No results.json file found. Cannot generate charts.")
        return {}

    with open(RESULTS_PATH, "r") as f:
        alerts = json.load(f)

    ioc_types = Counter()
    ml_priority = Counter()
    countries = Counter()
    mitre_techniques = Counter()
    risk_score_by_priority = defaultdict(list)

    for alert in alerts:
        ioc_types[alert.get("ioc_type", "unknown")] += 1
        priority = alert.get("ml_priority", "unclassified")
        ml_priority[priority] += 1
        country = alert.get("enrichment", {}).get("country", "unknown")
        countries[country] += 1

        # Average legacy_risk_score by priority
        legacy_score = alert.get("legacy_risk_score", 0)
        risk_score_by_priority[priority].append(legacy_score)

        mitre = alert.get("mitre_technique", {})
        mitre_id = mitre.get("id")
        mitre_name = mitre.get("name")
        if mitre_id and mitre_name:
            label = f"{mitre_id} – {mitre_name}"
            mitre_techniques[label] += 1

    risk_score_avg_by_priority = {
        k: round(sum(v) / len(v), 1) for k, v in risk_score_by_priority.items() if v
    }

    output = {
        "ioc_types": ioc_types.most_common(),
        "ml_priority": ml_priority.most_common(),
        "countries": countries.most_common(),
        "mitre_techniques": mitre_techniques.most_common(),
        "risk_score_avg_by_priority": risk_score_avg_by_priority
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[+] Threat intelligence chart data saved to: {OUTPUT_PATH}")
    return output