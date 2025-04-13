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
import os
import joblib
import pandas as pd
from functools import lru_cache

# Base project directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MODELS_DIR = os.path.join(BASE_DIR, "models")

# Minimal confirmation for startup context
print(f"[ML] BASE_DIR: {BASE_DIR}")
print(f"[ML] MODELS_DIR: {MODELS_DIR}")


def safe_transform(encoder, value, fallback=-1):
    try:
        return encoder.transform([value])[0]
    except ValueError as e:
        logging.warning(f"[ML] Unknown value '{value}' for encoder {encoder.__class__.__name__}: {e}")
        return fallback


# Cache the latest model path and loaded objects
def get_latest_model_dir():
    versions = [d for d in os.listdir(MODELS_DIR) if d.startswith("v")]
    versions.sort(reverse=True)
    if not versions:
        raise FileNotFoundError("No trained model versions found in /models")
    return os.path.join(MODELS_DIR, versions[0])


@lru_cache(maxsize=1)
def load_latest_model_and_encoders():
    model_dir = get_latest_model_dir()
    model = joblib.load(os.path.join(model_dir, "alert_classifier.joblib"))
    le_event = joblib.load(os.path.join(model_dir, "le_event.joblib"))
    le_country = joblib.load(os.path.join(model_dir, "le_country.joblib"))
    le_usage = joblib.load(os.path.join(model_dir, "le_usage.joblib"))
    le_action = joblib.load(os.path.join(model_dir, "le_action.joblib"))
    return model, le_event, le_country, le_usage, le_action


def classify_alert(alert: dict) -> str:
    """
    Classifies an alert using the latest trained ML model.
    If prediction fails, returns 'unclassified'.
    """
    try:
        model, le_event, le_country, le_usage, le_action = load_latest_model_and_encoders()

        event_type = alert.get("event_type", "")
        country = alert.get("enrichment", {}).get("country", "")
        usage_type = alert.get("enrichment", {}).get("usage_type", "")

        logging.info(f"[ML] Input received => event_type: {event_type}, country: {country}, usage_type: {usage_type}")

        event_type_enc = safe_transform(le_event, event_type)
        country_enc = safe_transform(le_country, country)
        usage_type_enc = safe_transform(le_usage, usage_type)

        logging.info(f"[ML] Encoded features => event_type_enc: {event_type_enc}, country_enc: {country_enc}, usage_type_enc: {usage_type_enc}")

        features = pd.DataFrame([[
            event_type_enc,
            alert.get("enrichment", {}).get("abuse_score", 0),
            alert.get("enrichment", {}).get("total_reports", 0),
            country_enc,
            usage_type_enc
        ]], columns=["event_type_enc", "abuse_score", "total_reports", "country_enc", "usage_type_enc"])

        prediction = model.predict(features)[0]
        logging.info(f"[ML] Raw prediction index: {prediction}")

        try:
            label = le_action.inverse_transform([prediction])[0]
            logging.info(f"[ML] Prediction label: {label}")
            return label
        except Exception as e:
            logging.warning(f"[ML] Failed to decode predicted label '{prediction}': {e}")
            return "unclassified"

    except Exception as e:
        logging.warning(f"[ML] Failed to classify alert: {e}")
        return "unclassified"
