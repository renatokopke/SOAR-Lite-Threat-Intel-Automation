# 🧾 Changelog

All notable changes to this project will be documented in this file.  
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.2.0] - 2025-04-18

### 🚀 Added
- Automatic webhook trigger system with visual rule editor
- Webhook configuration via UI with support for:
  - ML priority
  - Confidence score threshold
  - Optional event type
  - Rule enable/disable, edit, delete
  - Multiple rules per destination
- Slack integration with dynamic message enrichment:
  - Includes IOC, Type, Priority, Confidence, Risk Score, Event, Country, Source
  - Interactive button linking to the full report
- Report URL configurable via `.env` (`REPORT_URL`)
- IOC repetition detection (`ioc_seen_before`, `seen_count`, `last_seen`)
- Threat Overview page with aggregated stats (event types, countries, ML priorities)
- CSV export of alert results via `/export-results-csv`
- API usage documentation page (`/api-usage`)
- Support for legacy risk scoring (`legacy_risk_score`)
- MITRE ATT&CK technique mapping per event type
- Dashboard with model performance metrics (accuracy, precision, recall, F1)
- Fully modular FastAPI router structure by domain (`alerts`, `model`, `dashboard`, etc.)

### ⚙️ Changed
- ML classifier now returns both `ml_priority` and `confidence_score`
- HTML report enriched with more metadata (MITRE, ML, enrichment, risk, etc.)
- `reset-system` command clears all relevant state, including models and logs
- Slack message layout migrated to Block Kit for richer formatting and interactions

---

## [1.1.0] - 2025-04-12

### 🚀 Added
- Full web UI with the following pages:
  - Dashboard
  - Upload Alerts
  - Report
  - Train Model
  - Reset System
- Support for using the system entirely through the web interface
- Video demo added and embedded in README
- New layout with visual improvements and responsive design

### ⚙️ Changed
- Improved AI alert classification pipeline
- README fully reorganized for better onboarding and visual clarity
- `.env` documentation improved in the Quick Start section

---

## [1.0.0] - 2025-03-28

### 🚀 Added
- Initial version of SOAR-Lite with REST API
- Alert enrichment using AbuseIPDB or mock data
- Risk scoring and priority classification using ML
- Docker and `.env` support
- CSV upload via API (`/process-alert`)
- HTML report generation (`/report`)