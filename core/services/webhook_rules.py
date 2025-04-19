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

RULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "webhook_config.json"))


def load_rules() -> dict:
    if not os.path.exists(RULES_PATH):
        logging.warning("[WebhookRules] Config file not found, returning empty.")
        return {}
    try:
        with open(RULES_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"[WebhookRules] Error loading rules: {e}")
        return {}


def save_rules(config: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
        with open(RULES_PATH, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"[WebhookRules] Error saving rules: {e}")
        return False