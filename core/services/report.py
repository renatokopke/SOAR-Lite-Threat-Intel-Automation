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

        ioc_type = item.get("ioc_type", "ip")
        ioc_value = item.get("ioc_value", item.get("src_ip"))

        # Determine which sources were used
        sources = item.get("sources", {})
        used_sources = []
        if "abuseipdb" in sources:
            used_sources.append("AbuseIPDB")
        if "virustotal" in sources:
            used_sources.append("VirusTotal")
        sources_str = ", ".join(used_sources) if used_sources else "N/A"

        # MITRE ATT&CK rendering
        mitre_info = item.get("mitre_technique", {})
        tactic = mitre_info.get("tactic", "Unknown").lower()

        tactic_colors = {
            "discovery": "#007bff",
            "credential access": "#dc3545",
            "command and control": "#ffc107",
            "exfiltration": "#6f42c1",
            "unknown": "#6c757d"
        }

        color = tactic_colors.get(tactic, "#6c757d")

        mitre_str = f"""<div style='
            background-color:{color};
            color:white;
            padding:4px 6px;
            border-radius:4px;
            font-size:90%;
            display: inline-block;
            text-align: center;
            max-width: 220px;
        ' title="{mitre_info.get('id', 'T0000')} – {mitre_info.get('name', 'Unknown')}">
            <strong>{mitre_info.get('id', 'T0000')}</strong><br>
            <span style='font-size:85%;'>{mitre_info.get('name', 'Unknown')}</span>
        </div>"""

        seen_count = item.get("seen_count", 0)
        if seen_count > 0:
            seen_str = f"""<span class='badge bg-warning text-dark' title='Seen {seen_count} time(s) in previous alerts'>
            Seen {seen_count}x
            </span>"""
        else:
            seen_str = "<span class='text-muted'>–</span>"

        country = item['enrichment'].get('country', 'unknown')
        country_str = "<span class='text-muted'>–</span>" if country.lower() in ["unknown", "n/a"] else html.escape(country)

        priority_colors = {
            "block immediately": "danger",
            "escalate to tier 2": "warning text-dark",
            "monitor": "primary",
            "unclassified": "secondary text-white"
        }

        priority_key = predicted.lower()
        badge_class = priority_colors.get(priority_key, "secondary text-white")
        ml_str = f"<span class='badge bg-{badge_class}'>{html.escape(predicted)}</span>"

        confidence = item.get("confidence_score", 0)
        confidence_str = f"<span class='badge bg-info text-dark'>{confidence:.2f}</span>"

        table_rows += f"""
        <tr class="{highlight_class}">
            <td>{html.escape(item['timestamp'])}</td>
            <td>{html.escape(item['event_type'])}</td>
            <td>{html.escape(ioc_type)}</td>
            <td>{html.escape(ioc_value)}</td>
            <td>{seen_str}</td>
            <td>{country_str}</td>
            <td>{item['enrichment'].get('abuse_score', 'N/A')}</td>
            <td>{html.escape(sources_str)}</td>
            <td>{mitre_str}</td>
            <td>{item['risk_score']}</td>
            <td>{html.escape(suggested)}</td>
            <td>{ml_str}</td>
            <td>{confidence_str}</td>
        </tr>
        """

    # Load the full template HTML
    with open("templates/enriched_alert_report.html", "r", encoding="utf-8") as f:
        template = f.read()

    # Replace placeholders
    html_content = template.replace("{rows}", table_rows)
    html_content = html_content.replace("{discrepancy_count}", str(discrepancy_count))

    return html_content