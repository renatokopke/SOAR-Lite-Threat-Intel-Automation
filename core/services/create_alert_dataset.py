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

# Path to already processed results file
input_path = "../../output/results.json"
output_path = "../../data/dataset_for_ml.csv"

# Example of fictitious results for local simulation
example_data = [
    {
        "timestamp": "2025-04-03T10:30:00",
        "src_ip": "45.83.91.12",
        "event_type": "port_scan",
        "risk_score": 85,
        "suggested_action": "BLOCK IMMEDIATELY",
        "enrichment": {
            "abuse_score": 75,
            "country": "RU",
            "usage_type": "Data Center",
            "total_reports": 45,
            "last_reported_at": "2025-04-01T15:00:00Z"
        }
    },
    {
        "timestamp": "2025-04-03T10:32:00",
        "src_ip": "8.8.8.8",
        "event_type": "suspicious_login",
        "risk_score": 45,
        "suggested_action": "MONITOR",
        "enrichment": {
            "abuse_score": 0,
            "country": "US",
            "usage_type": "CDN",
            "total_reports": 0,
            "last_reported_at": None
        }
    }
]

if os.path.isfile(input_path) and os.path.getsize(input_path) > 0:
    print(f"For the dataset I am using the local file already generated as a base.")
    with open(input_path, "r") as f:
        data_file = json.load(f)
else:
    print(f"For the dataset I am using an example as a model to create an initial base.")
    data_file = example_data

# Process the data to assemble the dataset
records = []
for alert in data_file:
    enrichment = alert.get("enrichment", {})
    records.append({
        "event_type": alert.get("event_type"),
        "abuse_score": enrichment.get("abuse_score", 0),
        "country": enrichment.get("country", ""),
        "usage_type": enrichment.get("usage_type", ""),
        "total_reports": enrichment.get("total_reports", 0),
        "risk_score": alert.get("risk_score"),
        "suggested_action": alert.get("suggested_action")
    })

# Create the DataFrame and save as CSV
df = pd.DataFrame(records)
df.to_csv(output_path, index=False)