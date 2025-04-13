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
import csv
import json
import logging
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from core.services.enrichment import enrich_ip
from core.services.risk import calculate_risk_score
from core.services.actions import suggest_action
from core.services.report import generate_html_report
from core.services.ml_classifier import classify_alert, get_latest_model_dir, load_latest_model_and_encoders
from collections import Counter

import subprocess
from fastapi.responses import HTMLResponse
from fastapi import Request

load_dotenv()

logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(BASE_DIR, "output")
TRAIN_MODEL_DIR = os.path.join(BASE_DIR, "core/models")


@app.get("/")
def home():
    models_path = "models"
    has_models = any(name.startswith("v") for name in os.listdir(models_path)) if os.path.exists(models_path) else False

    with open("templates/index.html") as f:
        html = f.read()

    if not has_models:
        alert = """
        <div class="alert alert-warning text-center mt-4" role="alert">
            <i class="bi bi-exclamation-triangle-fill me-2"></i>
            No trained model found. Please <strong>train the model</strong> first, then <strong>upload your alerts</strong> to get started.
        </div>
        """
        html = html.replace("{model_alert}", alert)
    else:
        html = html.replace("{model_alert}", "")

    return HTMLResponse(content=html, status_code=200)


@app.post("/process-alert")
async def process_alert(request: Request, file: UploadFile = File(...)):
    results = []
    try:

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
            src_ip = row['src_ip']
            event_type = row['event_type']
            enrichment = enrich_ip(src_ip)
            risk_score = calculate_risk_score(enrichment, event_type)
            action = suggest_action(risk_score, event_type)

            result = {
                "timestamp": row['timestamp'],
                "src_ip": src_ip,
                "event_type": event_type,
                "risk_score": risk_score,
                "enrichment": enrichment,
                "suggested_action": action
            }

            # print(f"process_alert() -> result: {result}")

            # AI Classification
            ml_priority = classify_alert(result)

            # print(f"process_alert() -> ml_priority: {ml_priority}")

            result["ml_priority"] = ml_priority
            logging.info(f"Alert classified as '{ml_priority}' by ML model.")

            results.append(result)

        # Save results
        os.makedirs("output", exist_ok=True)
        with open("output/results.json", "w") as f:
            json.dump(results, f, indent=4)

        logging.info("API processing completed.")

        # Generate country stats
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

        # Check if request is from a browser (HTML form)
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


@app.get("/upload-alerts")
def upload_alerts_form():
    page_path = "templates/upload-alerts.html"
    fallback_path = "templates/train_fallback.html"
    fallback_page_title = "Upload Alerts"

    try:
        _ = get_latest_model_dir()
    except FileNotFoundError:
        with open(fallback_path, "r", encoding="utf-8") as f:
            html = f.read().replace("{page_title}", fallback_page_title)
            return HTMLResponse(content=html, status_code=200)

    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    else:
        with open(fallback_path, "r", encoding="utf-8") as f:
            html = f.read().replace("{page_title}", fallback_page_title)
            return HTMLResponse(content=html, status_code=200)


@app.get("/report")
def get_report():
    page_path = "/results.json"
    fallback_path = "templates/train_fallback.html"
    fallback_page_title = "Report"

    try:
        _ = get_latest_model_dir()
    except FileNotFoundError:
        with open(fallback_path, "r", encoding="utf-8") as f:
            html = f.read().replace("{page_title}", fallback_page_title)
            return HTMLResponse(content=html, status_code=200)

    try:
        html = generate_html_report(REPORT_DIR + page_path)
        return HTMLResponse(content=html, status_code=200)
    except Exception as e:
        logging.error(f"Error generating report: {e}")

        with open("templates/report_fallback_modal.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=400)


@app.post("/train-model")
def train_model():
    try:
        result = subprocess.run(
            ["python3", os.path.join(TRAIN_MODEL_DIR, "train_alert_classifier.py")],
            check=True,
            capture_output=True,
            text=True
        )

        # Ensures that the next classification use the newly trained model
        load_latest_model_and_encoders.cache_clear()

        return HTMLResponse(content="""
            <html>
            <head><meta http-equiv="refresh" content="2;url=/dashboard" /></head>
            <body>
                <p>Model retrained successfully. Redirecting to dashboard...</p>
            </body>
            </html>
        """, status_code=200)

    except subprocess.CalledProcessError as e:
        return JSONResponse(
            content={
                "error": "Training failed.",
                "stdout": e.stdout,
                "stderr": e.stderr
            },
            status_code=500
        )


@app.get("/dashboard")
def get_dashboard():
    page_path = "static/public/artifacts/dashboard.html"
    fallback_path = "templates/train_fallback.html"
    fallback_page_title = "Dashboard"

    try:
        _ = get_latest_model_dir()
    except FileNotFoundError:
        with open(fallback_path, "r", encoding="utf-8") as f:
            html = f.read().replace("{page_title}", fallback_page_title)
            return HTMLResponse(content=html, status_code=200)

    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    else:
        with open(fallback_path, "r", encoding="utf-8") as f:
            html = f.read().replace("{page_title}", fallback_page_title)
            return HTMLResponse(content=html, status_code=200)


@app.post("/reset-system")
def reset_system():
    try:
        import shutil

        models_dir = os.path.join(BASE_DIR, "models")
        if os.path.isdir(models_dir):
            for item in os.listdir(models_dir):
                path = os.path.join(models_dir, item)
                if os.path.isdir(path):
                    shutil.rmtree(path)

        for path in [
            os.path.join(BASE_DIR, "output", "results.json"),
            os.path.join(BASE_DIR, "logs", "app.log")
        ]:
            if os.path.exists(path):
                os.remove(path)

        artifacts_dir = os.path.join(BASE_DIR, "static", "public", "artifacts")
        if os.path.isdir(artifacts_dir):
            shutil.rmtree(artifacts_dir)

        load_latest_model_and_encoders.cache_clear()

        return HTMLResponse(content="""
            <html>
            <head><meta http-equiv="refresh" content="2;url=/" /></head>
            <body>
                <p>System reset successfully. Redirecting to home...</p>
            </body>
            </html>
        """)

    except Exception as e:
        logging.error(f"Failed to reset system: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)
