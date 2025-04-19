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
import pandas as pd
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import io
from core.version import __version__

router = APIRouter()
templates = Jinja2Templates(directory="templates")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


@router.get("/export-results-csv")
def export_results_csv():
    try:
        with open("output/results.json", "r") as f:
            data = json.load(f)

        df = pd.json_normalize(data)
        csv_data = df.to_csv(index=False)

        return StreamingResponse(io.StringIO(csv_data), media_type="text/csv", headers={
            "Content-Disposition": "attachment; filename=alerts_export.csv"
        })

    except Exception as e:
        logging.error(f"Failed to export CSV: {e}")
        return JSONResponse(content={"error": str(e)}, status_code=500)


@router.get("/api-usage")
def api_usage(request: Request):
    return templates.TemplateResponse("api_usage.html", {"request": request, "version": __version__})
