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

from dotenv import load_dotenv
import os
import requests

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY
}


def get_ip_report(ip):
    url = f"{VT_BASE_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error {response.status_code} from VirusTotal"}


def get_domain_report(domain):
    url = f"{VT_BASE_URL}/domains/{domain}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error {response.status_code} from VirusTotal"}


def get_file_hash_report(file_hash):
    url = f"{VT_BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error {response.status_code} from VirusTotal"}


def get_url_report(url_to_check):
    import base64
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    url = f"{VT_BASE_URL}/urls/{url_id}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error {response.status_code} from VirusTotal"}
