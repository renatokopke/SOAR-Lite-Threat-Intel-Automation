# SOAR-Lite Threat Intel Automation

A lightweight, modular, and real-time SOAR-like API designed to enrich security alerts with threat intelligence, calculate contextual risk scores, and recommend response actions (block, escalate, monitor). Ideal for SOC teams, security engineers, or incident responders looking to automate triage and reduce alert fatigue without the complexity or cost of full SOAR platforms.

---
## 🔍 Features

- ✅ IP enrichment using [AbuseIPDB](https://www.abuseipdb.com) or mock data
- ✅ Risk scoring based on alert type and IP reputation
- ✅ Automated response suggestions (block, escalate, monitor)
- ✅ HTML report generation for visual review and auditing
- ✅ Real-time REST API
- ✅ Dockerized and easy to run locally or in the cloud
---

## 👤 Author

**Renato Silva Kopke**  
Cybersecurity • Incident Response • Threat Hunting • Automation Enthusiast  
Licensed under the [Apache License 2.0](./LICENSE)


---
## 🚀 Getting Started

### 📦 Prerequisites

- [Docker](https://www.docker.com/products/docker-desktop)
- [Docker Compose](https://docs.docker.com/compose/install/)
- AbuseIPDB API key (optional if using debug mode)
---

### 📁 Clone the repository

```bash
git clone https://github.com/renatokopke/SOAR-Lite-Threat-Intel-Automation.git
cd SOAR-Lite-Threat-Intel-Automation
```

### Configure .env
Edit the .env file:
```
ABUSEIPDB_API_KEY=your_api_key_here
DEBUG_MODE=true         # Set to false to use real API enrichment
```

🐳 Run with Docker Compose
```
docker-compose up --build
```
This will:

- Build the image
- Install dependencies
- Run the FastAPI application on port 8000

### API Endpoints
### `POST /process-alert`
- Upload a CSV file with alerts (timestamp, src_ip, dst_ip, event_type)
- Returns enriched alerts with risk score and action
```
curl -X POST "http://localhost:8000/process-alert" -F "file=@data/alerts.csv"
```

### `GET /report`
- Displays an HTML report with all processed alerts
Open in your browser:
👉 http://localhost:8000/report


### 📊 Example Input (CSV)
```
timestamp,src_ip,dst_ip,event_type
2025-04-03T10:30:00,45.83.91.12,10.0.0.15,port_scan
2025-04-03T10:32:00,82.94.243.11,10.0.0.21,suspicious_login
```

### 📖 License

Licensed under the [Apache License 2.0](./LICENSE)

### 🙋‍♂️ About the Author

Created by Renato Silva Kopke, cybersecurity focused on incident response, automation, and practical engineering.

Feel free to connect or reach out on [LinkedIn](https://linkedin.com/in/renatokopke) if you'd like to collaborate or share feedback.