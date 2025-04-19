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

from fastapi import APIRouter, UploadFile, File, Request
from fastapi.responses import JSONResponse, HTMLResponse
from core.services.ml_classifier import classify_alert, get_latest_model_dir
from core.services.enrichment.fusion import enrich_ioc
from core.services.attck_mapper import map_event_to_mitre
from core.services.actions import suggest_action
from core.services.create_alert_dataset import generate_dataset_from_results
from core.services.integrations.webhook import should_trigger_webhook
from core.services.integrations.webhook_slack import send_webhook_to_slack
from core.services.risk import calculate_risk_score
import os, csv, json, logging
from collections import Counter

router = APIRouter()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


@router.post("/process-alert")
async def process_alert(request: Request, file: UploadFile = File(...)):
    results = []
    try:
        previous_results = []
        try:
            with open("output/results.json", "r") as f:
                previous_results = json.load(f)
        except Exception:
            previous_results = []

        ioc_history = {}
        for r in previous_results:
            ioc_key = f"{r.get('ioc_type')}::{r.get('ioc_value')}"
            if ioc_key not in ioc_history:
                ioc_history[ioc_key] = []
            ioc_history[ioc_key].append(r.get("timestamp"))

        try:
            _ = get_latest_model_dir()
        except FileNotFoundError:
            return JSONResponse(
                content={"error": "No trained model found. Please train the model before processing alerts."},
                status_code=400
            )

        content = await file.read()
        lines = content.decode().splitlines()
        reader = csv.DictReader(lines)

        for row in reader:
            event_type = row['event_type']
            ioc_type = row.get("ioc_type", "ip")
            ioc_value = row.get("ioc_value") or row.get("src_ip")

            fusion_data = enrich_ioc(ioc_type, ioc_value)
            abuse_data = fusion_data["sources"].get("abuseipdb", {})
            simplified_enrichment = {
                "abuse_score": abuse_data.get("abuse_score", 0),
                "country": abuse_data.get("country", "unknown"),
                "usage_type": abuse_data.get("usage_type", "unknown"),
                "total_reports": abuse_data.get("total_reports", 0),
                "source": "fusion"
            }

            legacy_score = calculate_risk_score(abuse_data, event_type)
            risk_score = fusion_data.get("risk_score", 0)
            action = suggest_action(risk_score, event_type)

            result = {
                "timestamp": row["timestamp"],
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "event_type": event_type,
                "risk_score": risk_score,
                "legacy_risk_score": legacy_score,
                "enrichment": simplified_enrichment,
                "suggested_action": action,
                "sources": fusion_data.get("sources", {})
            }

            ioc_key = f"{ioc_type}::{ioc_value}"
            timestamps = ioc_history.get(ioc_key, [])
            if timestamps:
                result["ioc_seen_before"] = True
                result["seen_count"] = len(timestamps)
                result["last_seen"] = sorted(timestamps)[-1]
            else:
                result["ioc_seen_before"] = False
                result["seen_count"] = 0
                result["last_seen"] = None

            result["mitre_technique"] = map_event_to_mitre(event_type)
            ml_priority, confidence = classify_alert(result)
            result["ml_priority"] = ml_priority
            result["confidence_score"] = round(confidence, 3)

            if should_trigger_webhook(result, destination="slack"):
                send_webhook_to_slack(result)

            logging.info(f"Alert classified as '{ml_priority}' by ML model.")
            results.append(result)

        os.makedirs("output", exist_ok=True)
        with open("output/results.json", "w") as f:
            json.dump(results, f, indent=4)

        generate_dataset_from_results()
        logging.info("dataset_for_ml.csv updated after processing alerts.")

        try:
            counter = Counter()
            for alert in results:
                country = alert.get("enrichment", {}).get("country")
                score = alert.get("risk_score", 0)
                if country and score >= 80:
                    counter[country] += 1

            top_countries = [c for c, _ in counter.most_common(15)]
            os.makedirs("data", exist_ok=True)
            with open("data/high_abuse_countries.json", "w") as f:
                json.dump(top_countries, f, indent=2)
            logging.info(f"Updated local statistics by country: {top_countries}")
        except Exception as e:
            logging.warning(f"Error updating local statistics by country: {e}")

        if "text/html" in request.headers.get("accept", ""):
            return HTMLResponse(content="""
                <html>
                <head><meta http-equiv="refresh" content="2;url=/report" /></head>
                <body>
                    <p>Alerts processed successfully. Redirecting to report...</p>
                </body>
                </html>
            """, status_code=200)

        return JSONResponse(content=results)

    except Exception as e:
        logging.error(f"Error API: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)