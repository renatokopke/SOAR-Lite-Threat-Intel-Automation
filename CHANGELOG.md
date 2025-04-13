# Changelog

All notable changes to this project will be documented in this file.  
This project adheres to [Semantic Versioning](https://semver.org/).

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
