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

HIGH_RISK_THRESHOLD = int(os.getenv("HIGH_RISK_THRESHOLD", 80))
MEDIUM_RISK_THRESHOLD = int(os.getenv("MEDIUM_RISK_THRESHOLD", 50))


def suggest_action(score, event_type):
    """
    Suggests an action based on the risk score.
    """
    if score >= HIGH_RISK_THRESHOLD:
        return "BLOCK IMMEDIATELY"
    elif score >= MEDIUM_RISK_THRESHOLD:
        return "ESCALATE TO TIER 2"
    else:
        return "MONITOR"