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
import logging
from dotenv import load_dotenv

load_dotenv()

CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "webhook_config.json"))


def should_trigger_webhook(alert: dict, destination: str = "slack") -> bool:
    if not os.path.exists(CONFIG_PATH):
        logging.warning("[Webhook] No webhook_config.json found. Skipping webhook trigger.")
        return False

    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)

        rules_list = config.get(destination)
        if not rules_list:
            return False

        if isinstance(rules_list, dict):
            rules_list = [rules_list]

        alert_priority = alert.get("ml_priority", "").upper()
        confidence = alert.get("confidence_score", 0)
        alert_event = alert.get("event_type", "")

        for rule in rules_list:
            if not rule.get("enabled", True):
                continue

            ml_triggers = rule.get("ml_priority", [])
            min_confidence = rule.get("confidence_score_min", 0)
            valid_events = rule.get("event_type", [])

            logging.info(
                f"[Webhook] Evaluating rule: priority={ml_triggers}, min_conf={min_confidence}, events={valid_events}")
            logging.info(f"[Webhook] Alert: priority={alert_priority}, conf={confidence}, event={alert_event}")

            if alert_priority in [x.upper() for x in ml_triggers] and confidence >= min_confidence:
                if valid_events:
                    if alert_event in valid_events:
                        return True
                else:
                    return True

    except Exception as e:
        logging.error(f"[Webhook] Error evaluating trigger rules: {e}")

    return False