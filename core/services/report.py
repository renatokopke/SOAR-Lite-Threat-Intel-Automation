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
import html

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def generate_html_report(json_path):
    """
    Generates an HTML report with enriched alerts including ML prediction.
    Highlights discrepancies between suggested_action and ml_priority.
    """
    with open(json_path, 'r') as f:
        results = json.load(f)

    results.sort(key=lambda x: x.get("timestamp", ""))
    discrepancy_count = 0
    table_rows = ""

    for item in results:
        suggested = item.get("suggested_action", "")
        predicted = item.get("ml_priority", "N/A")

        if suggested != predicted:
            highlight_class = "table-warning"
            discrepancy_count += 1
        else:
            highlight_class = ""

        table_rows += f"""
        <tr class="{highlight_class}">
            <td>{html.escape(item['timestamp'])}</td>
            <td>{html.escape(item['src_ip'])}</td>
            <td>{html.escape(item['event_type'])}</td>
            <td>{item['risk_score']}</td>
            <td>{html.escape(suggested)}</td>
            <td>{html.escape(predicted)}</td>
            <td>{html.escape(item['enrichment'].get('country', 'N/A'))}</td>
            <td>{item['enrichment'].get('abuse_score', 'N/A')}</td>
        </tr>
        """

    # Load the full template HTML
    with open("templates/enriched_alert_report.html", "r", encoding="utf-8") as f:
        template = f.read()

    # Replace placeholders
    html_content = template.replace("{rows}", table_rows)
    html_content = html_content.replace("{discrepancy_count}", str(discrepancy_count))

    return html_content