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
import logging
import requests
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("WEBHOOK_URL")

REPORT_URL = os.getenv("REPORT_URL", "http://localhost:8000/report")


def send_webhook_to_slack(alert: dict):
    if not SLACK_WEBHOOK_URL or not SLACK_WEBHOOK_URL.startswith("https://hooks.slack.com/"):
        logging.warning("[Slack] WEBHOOK_URL not set or invalid.")
        return

    ioc = alert.get("ioc_value", "N/A")
    ioc_type = alert.get("ioc_type", "N/A")
    event_type = alert.get("event_type", "N/A")
    priority = alert.get("ml_priority", "N/A")
    confidence = alert.get("confidence_score", 0)
    risk = alert.get("risk_score", 0)
    country = alert.get("enrichment", {}).get("country", "N/A")
    sources = ", ".join(alert.get("sources", {}).keys()) or "N/A"

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🚨 SOAR Lite – New Alert Notification*\n*IOC:* `{ioc}`  | *Type:* `{ioc_type}`\n*Priority:* `{priority}`  | *Confidence:* `{confidence:.2f}`\n*Risk:* `{risk}`  | *Country:* `{country}`\n*Event:* `{event_type}`  | *Sources:* `{sources}`"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🔎 View Full Report"
                        },
                        "url": REPORT_URL,
                        "style": "primary"
                    }
                ]
            }
        ]
    }

    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        if response.status_code == 200:
            logging.info(f"[Slack] Alert sent: {ioc} [{priority}]")
        else:
            logging.warning(f"[Slack] Failed to send: {response.status_code} - {response.text}")
    except Exception as e:
        logging.error(f"[Slack] Exception during send: {e}")