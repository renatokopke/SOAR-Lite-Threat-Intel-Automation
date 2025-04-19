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

# SOAR Lite – MITRE ATT&CK Mapper
MITRE_MAPPINGS = {
    "port_scan": {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery"
    },
    "suspicious_login": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Credential Access"
    },
    "malware_traffic": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control"
    },
    "brute_force": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },
    "data_exfiltration": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration"
    },
    "c2_traffic": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control"
    }
}


def map_event_to_mitre(event_type: str) -> dict:
    return MITRE_MAPPINGS.get(event_type.lower(), {
        "id": "T0000",
        "name": "Unknown or Unmapped Technique",
        "tactic": "Unknown"
    })
