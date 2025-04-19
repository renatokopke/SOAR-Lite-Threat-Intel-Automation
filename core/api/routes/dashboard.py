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
import logging
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from core.services.ml_classifier import get_latest_model_dir
from core.services.report import generate_html_report
from core.services.generate_threat_data import generate_threat_data
from core.version import __version__
from fastapi.templating import Jinja2Templates
from fastapi import Request

router = APIRouter()
templates = Jinja2Templates(directory="templates")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REPORT_DIR = os.path.join(BASE_DIR, "output")


@router.get("/report")
def get_report(request: Request):
    page_path = "/results.json"
    fallback_page_title = "Report"

    try:
        _ = get_latest_model_dir()
    except FileNotFoundError:
        return templates.TemplateResponse("train_fallback.html", {
            "request": request,
            "page_title": fallback_page_title,
            "version": __version__
        })

    try:
        html = generate_html_report(REPORT_DIR + page_path)
        html = html.replace("{{ version }}", __version__)
        return HTMLResponse(content=html, status_code=200)
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        return templates.TemplateResponse("report_fallback_modal.html", {
            "request": request,
            "version": __version__
        }, status_code=400)


@router.get("/dashboard")
def get_dashboard(request: Request):
    page_path = "static/public/artifacts/dashboard.html"
    fallback_page_title = "Dashboard - Model Performance"

    try:
        _ = get_latest_model_dir()
    except FileNotFoundError:
        return templates.TemplateResponse("train_fallback.html", {
            "request": request,
            "page_title": fallback_page_title,
            "version": __version__
        })

    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            html = f.read()
            html = html.replace("{{ version }}", __version__)
        return HTMLResponse(content=html, status_code=200)
    else:
        return templates.TemplateResponse("train_fallback.html", {
            "request": request,
            "page_title": fallback_page_title,
            "version": __version__
        })


@router.get("/threat-overview")
def threat_overview(request: Request):
    page_path = BASE_DIR+"/output/results.json"
    fallback_page_title = "Dashboard - Threat Intelligence Overview"

    try:
        _ = get_latest_model_dir()
    except FileNotFoundError:
        return templates.TemplateResponse("train_fallback.html", {
            "request": request,
            "page_title": fallback_page_title,
            "version": __version__
        })

    try:
        if os.path.exists(page_path):
            data = generate_threat_data()
            return templates.TemplateResponse("threat_overview.html",
                                              {"request": request, "data": data, "version": __version__})
        else:
            return templates.TemplateResponse("report_fallback_modal.html", {
                "request": request,
                "version": __version__
            }, status_code=400)

    except Exception as e:
        logging.error(f"Error generating report: {e}")
        return templates.TemplateResponse("report_fallback_modal.html", {
            "request": request,
            "version": __version__
        }, status_code=400)