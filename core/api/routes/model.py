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
import subprocess
import shutil
import logging
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from core.services.ml_classifier import load_latest_model_and_encoders, get_latest_model_dir

router = APIRouter()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
TRAIN_MODEL_DIR = os.path.join(BASE_DIR, "core/models")


@router.post("/train-model")
def train_model():
    try:
        result = subprocess.run(
            ["python3", os.path.join(TRAIN_MODEL_DIR, "train_alert_classifier.py")],
            check=True,
            capture_output=True,
            text=True
        )

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


@router.post("/reset-system")
def reset_system():
    try:
        models_dir = os.path.join(BASE_DIR, "models")
        if os.path.isdir(models_dir):
            for item in os.listdir(models_dir):
                path = os.path.join(models_dir, item)
                if os.path.isdir(path):
                    shutil.rmtree(path)

        for path in [
            os.path.join(BASE_DIR, "output", "results.json"),
            os.path.join(BASE_DIR, "data", "dataset_for_ml.csv"),
            os.path.join(BASE_DIR, "data", "high_abuse_countries.json"),
            os.path.join(BASE_DIR, "data", "threat_data.json"),
            os.path.join(BASE_DIR, "data", "webhook_config.json"),
            os.path.join(BASE_DIR, "logs", "app.log"),
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