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

from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from core.services.webhook_rules import load_rules, save_rules
from core.version import __version__

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/webhook-rules")
def get_webhook_rules(request: Request):
    config = load_rules()
    return templates.TemplateResponse("webhook_rules.html", {"request": request, "config": config, "version": __version__})


@router.post("/webhook-rules")
def update_webhook_rules(
    destination: str = Form(...),
    ml_priority: list[str] = Form(...),
    event_type: list[str] = Form(None),
    confidence_score_min: float = Form(...),
    edit_index: int = Form(None)
):
    current = load_rules()

    new_rule = {
        "ml_priority": ml_priority,
        "confidence_score_min": confidence_score_min,
        "enabled": True
    }
    if event_type:
        new_rule["event_type"] = event_type

    if destination not in current:
        current[destination] = []

    if isinstance(current[destination], dict):
        current[destination] = [current[destination]]

    if edit_index is not None and 0 <= edit_index < len(current[destination]):
        current[destination][edit_index] = new_rule
    else:
        current[destination].append(new_rule)

    save_rules(current)
    return RedirectResponse(url="/webhook-rules", status_code=302)


@router.post("/webhook-rules/delete")
def delete_webhook_rule(request: Request, destination: str = Form(...), index: int = Form(...)):
    config = load_rules()
    if destination in config and isinstance(config[destination], list):
        if 0 <= index < len(config[destination]):
            config[destination].pop(index)
            if not config[destination]:
                del config[destination]
            save_rules(config)
    return RedirectResponse(url="/webhook-rules", status_code=302)


@router.post("/webhook-rules/toggle")
def toggle_webhook_rule(request: Request, destination: str = Form(...), index: int = Form(...)):
    config = load_rules()
    if destination in config and isinstance(config[destination], list) and 0 <= index < len(config[destination]):
        current_value = config[destination][index].get("enabled", True)
        config[destination][index]["enabled"] = not current_value
        save_rules(config)
    return RedirectResponse(url="/webhook-rules", status_code=302)


@router.post("/webhook-rules/edit")
async def edit_webhook_rule(request: Request, destination: str = Form(...), index: int = Form(...)):
    config = load_rules()
    rule = config.get(destination, [])[index]
    return templates.TemplateResponse("webhook_rules.html", {
        "request": request,
        "config": config,
        "edit_destination": destination,
        "edit_index": index,
        "edit_rule": rule,
        "version": __version__
    })