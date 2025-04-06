# Author: Renato Kopke
# github.com/renatokopke
# Date: April 2025

import os
import csv
import json
import logging
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse, HTMLResponse
from dotenv import load_dotenv
from utils.enrichment import enrich_ip
from utils.risk import calculate_risk_score
from utils.actions import suggest_action
from utils.report import generate_html_report
from collections import Counter

load_dotenv()

logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = FastAPI()

@app.post("/process-alert")
async def process_alert(file: UploadFile = File(...)):
    results = []
    try:
        content = await file.read()
        lines = content.decode().splitlines()
        reader = csv.DictReader(lines)

        for row in reader:
            src_ip = row['src_ip']
            event_type = row['event_type']
            enrichment = enrich_ip(src_ip)
            risk_score = calculate_risk_score(enrichment, event_type)
            action = suggest_action(risk_score, event_type)

            result = {
                "timestamp": row['timestamp'],
                "src_ip": src_ip,
                "event_type": event_type,
                "risk_score": risk_score,
                "enrichment": enrichment,
                "suggested_action": action
            }
            results.append(result)

        # Save JSON result
        os.makedirs("output", exist_ok=True)
        with open("output/results.json", "w") as f:
            json.dump(results, f, indent=4)

        logging.info("API processing completed.")

        # Generates local statistics by country
        try:
            counter = Counter()
            for alert in results:
                country = alert.get("enrichment", {}).get("country")
                score = alert.get("risk_score", 0)
                if country and score >= 80:
                    counter[country] += 1

            top_countries = [c for c, _ in counter.most_common(15)]
            os.makedirs("data", exist_ok=True)
            with open("data/high_abuse_countries.json", "w") as f:
                json.dump(top_countries, f, indent=2)
            logging.info(f"Updated local statistics by country: {top_countries}")
        except Exception as e:
            logging.warning(f"Error updating local statistics by country: {e}")

        return JSONResponse(content=results)

    except Exception as e:
        logging.error(f"Erro na API: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/report")
def get_report():
    try:
        html = generate_html_report("output/results.json")
        return HTMLResponse(content=html, status_code=200)
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)