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

import json
import pandas as pd
import os
from core.services.risk import calculate_risk_score

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INPUT_PATH = os.path.join(BASE_DIR, "output", "results.json")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "dataset_for_ml.csv")


def generate_dataset_from_results():
    try:
        with open(INPUT_PATH, "r") as f:
            data_file = json.load(f)
    except Exception as e:
        print(f"[!] Could not read input file for dataset generation. Exception: {e}")
        return

    records = []
    for alert in data_file:
        enrichment = alert.get("enrichment", {})
        legacy_score = alert.get("legacy_risk_score", calculate_risk_score(enrichment, alert.get("event_type", "")))

        records.append({
            "event_type": alert.get("event_type", ""),
            "abuse_score": enrichment.get("abuse_score", 0),
            "country": enrichment.get("country", "unknown"),
            "usage_type": enrichment.get("usage_type", "unknown"),
            "total_reports": enrichment.get("total_reports", 0),
            "risk_score": alert.get("risk_score", 0),
            "legacy_risk_score": legacy_score,
            "suggested_action": alert.get("suggested_action", "unclassified")
        })

    df = pd.DataFrame(records)
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"[+] dataset_for_ml.csv updated with {len(records)} records.")


# Dados fictícios para fallback local
example_data = [
    {
        "timestamp": "2025-04-03T10:30:00",
        "src_ip": "45.83.91.12",
        "event_type": "port_scan",
        "risk_score": 85,
        "legacy_risk_score": 70,
        "suggested_action": "BLOCK IMMEDIATELY",
        "enrichment": {
            "abuse_score": 75,
            "country": "RU",
            "usage_type": "Data Center/Web Hosting/Transit",
            "total_reports": 45,
            "last_reported_at": "2025-04-01T15:00:00Z"
        }
    },
    {
        "timestamp": "2025-04-03T10:32:00",
        "src_ip": "8.8.8.8",
        "event_type": "suspicious_login",
        "risk_score": 45,
        "legacy_risk_score": 40,
        "suggested_action": "MONITOR",
        "enrichment": {
            "abuse_score": 0,
            "country": "US",
            "usage_type": "Content Delivery Network",
            "total_reports": 0,
            "last_reported_at": None
        }
    }
]

# Load data from the last saved enrichment or use dummy data
if os.path.isfile(INPUT_PATH) and os.path.getsize(INPUT_PATH) > 0:
    print(f"[+] Loading enrichment data from '{INPUT_PATH}'")
    with open(INPUT_PATH, "r") as f:
        data_file = json.load(f)
else:
    print("[!] Results file not found. Using sample data.")
    data_file = example_data

# Assemble the dataset with the REAL values coming from the API (without modification!)
records = []
for alert in data_file:
    enrichment = alert.get("enrichment", {})
    legacy_score = alert.get("legacy_risk_score", calculate_risk_score(enrichment, alert.get("event_type", "")))

    records.append({
        "event_type": alert.get("event_type", ""),
        "abuse_score": enrichment.get("abuse_score", 0),
        "country": enrichment.get("country", "unknown"),
        "usage_type": enrichment.get("usage_type", "unknown"),
        "total_reports": enrichment.get("total_reports", 0),
        "risk_score": alert.get("risk_score", 0),
        "legacy_risk_score": legacy_score,
        "suggested_action": alert.get("suggested_action", "unclassified")
    })

# Save the new dataset
df = pd.DataFrame(records)
df.to_csv(OUTPUT_PATH, index=False)
print(f"[+] Dataset successfully saved to: {OUTPUT_PATH}")