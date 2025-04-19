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
from fastapi import APIRouter
from core.services.ml_classifier import get_latest_model_dir
from fastapi import Request
from fastapi.templating import Jinja2Templates
from core.version import __version__

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/upload-alerts")
def upload_alerts_form(request: Request):
    page_path = "templates/upload-alerts.html"
    fallback_path = "train_fallback.html"
    fallback_page_title = "Upload Alerts"

    try:
        _ = get_latest_model_dir()
    except FileNotFoundError:
        return templates.TemplateResponse(fallback_path, {
            "request": request,
            "page_title": fallback_page_title,
            "version": __version__
        })

    if os.path.exists(page_path):
        return templates.TemplateResponse("upload-alerts.html", {
            "request": request,
            "version": __version__
        })
    else:
        return templates.TemplateResponse("train_fallback.html", {
            "request": request,
            "page_title": fallback_page_title,
            "version": __version__
        })