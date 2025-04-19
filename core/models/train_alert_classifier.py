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
import sys
from datetime import datetime
from collections import Counter
import joblib
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
import plotly.graph_objects as go

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from core.services.create_alert_dataset import example_data

import logging
logging.basicConfig(level=logging.INFO)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

data_path = os.path.join(BASE_DIR, "data", "dataset_for_ml.csv")
model_base_dir = os.path.join(BASE_DIR, "models")
report_dir = os.path.join(BASE_DIR, "static", "public", "artifacts", "reports")
charts_dir = os.path.join(BASE_DIR, "static", "public", "artifacts", "charts")
metrics_path = os.path.join(BASE_DIR, "static", "public", "artifacts", "metrics.csv")
template_path = os.path.join(BASE_DIR, "templates", "dashboard_template.html")
output_dashboard = os.path.join(BASE_DIR, "static", "public", "artifacts", "dashboard.html")

os.makedirs(model_base_dir, exist_ok=True)
os.makedirs(report_dir, exist_ok=True)
os.makedirs(charts_dir, exist_ok=True)

# Load dataset
df = pd.read_csv(data_path)


# Validate dataset before proceeding
def is_dataset_ready(df):
    if df.empty:
        return False
    if "suggested_action" not in df.columns:
        return False
    if len(df["suggested_action"].unique()) < 2:
        return False
    return True


if not is_dataset_ready(df):
    logging.info("[!] Insufficient or missing data in dataset_for_ml.csv.")
    logging.info("[!] Using example fallback dataset to initialize the model...")

    df = pd.DataFrame(example_data)

le_event, le_country, le_usage, le_action = LabelEncoder(), LabelEncoder(), LabelEncoder(), LabelEncoder()
df["event_type_enc"] = le_event.fit_transform(df["event_type"])
df["country_enc"] = le_country.fit_transform(df["country"])
df["usage_type_enc"] = le_usage.fit_transform(df["usage_type"])
df["action_enc"] = le_action.fit_transform(df["suggested_action"])

X = df[["event_type_enc", "abuse_score", "total_reports", "country_enc", "usage_type_enc", "legacy_risk_score"]]
y = df["action_enc"]
stratify_param = y if min(Counter(y).values()) >= 2 else None

from math import ceil

num_classes = y.nunique()
min_test_size = min(max(3, ceil(len(y) * 0.2)), len(y) - 1)

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=min_test_size,
    stratify=stratify_param,
    random_state=42
)

logging.info(f"Number of classes: {num_classes}, selected test_size: {min_test_size}")

# Training model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

# Metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average="macro", zero_division=0)
recall = recall_score(y_test, y_pred, average="macro", zero_division=0)
f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
support = len(y_test)
report = classification_report(y_test, y_pred, labels=le_action.transform(le_action.classes_), target_names=le_action.classes_, zero_division=0)

# Version
version = datetime.now().strftime("v%Y%m%d-%H%M%S")
version_dir = os.path.join(model_base_dir, version)
os.makedirs(version_dir, exist_ok=True)

# Model Save and encoders
joblib.dump(model, os.path.join(version_dir, "alert_classifier.joblib"))
joblib.dump(le_event, os.path.join(version_dir, "le_event.joblib"))
joblib.dump(le_country, os.path.join(version_dir, "le_country.joblib"))
joblib.dump(le_usage, os.path.join(version_dir, "le_usage.joblib"))
joblib.dump(le_action, os.path.join(version_dir, "le_action.joblib"))

# Save report
with open(os.path.join(report_dir, f"report_{version}.txt"), "w") as f:
    f.write(f"Accuracy: {accuracy:.2f}\n")
    f.write(f"Precision (macro): {precision:.2f}\n")
    f.write(f"Recall (macro): {recall:.2f}\n")
    f.write(f"F1-score (macro): {f1:.2f}\n")
    f.write(f"Support: {support}\n\n")
    f.write(report)

# Update metrics.csv
df_metrics = pd.DataFrame([[version, accuracy, precision, recall, f1, support]],
    columns=["version", "accuracy", "precision_macro", "recall_macro", "f1_macro", "support"])
if os.path.exists(metrics_path):
    df_metrics_all = pd.read_csv(metrics_path)
    df_metrics_all = pd.concat([df_metrics_all, df_metrics], ignore_index=True)
else:
    df_metrics_all = df_metrics
df_metrics_all.to_csv(metrics_path, index=False)

# Generates static graphics (.png)
df_metrics_all["accuracy"] *= 100
df_metrics_all["precision_macro"] *= 100
df_metrics_all["recall_macro"] *= 100
df_metrics_all["f1_macro"] *= 100

for metric in ["accuracy", "precision_macro", "recall_macro", "f1_macro"]:
    plt.figure(figsize=(10, 5))
    plt.plot(df_metrics_all["version"], df_metrics_all[metric], marker="o", linestyle="-")
    plt.title(f"{metric.replace('_', ' ').title()} Over Versions")
    plt.xlabel("Model Version")
    plt.ylabel(f"{metric.replace('_', ' ').title()} (%)")
    plt.xticks(rotation=45)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(charts_dir, f"model_{metric}.png"))
    plt.close()

# Generates interactive graphics with Plotly
for metric in ["accuracy", "precision_macro", "recall_macro", "f1_macro"]:
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df_metrics_all["version"],
        y=df_metrics_all[metric],
        mode='lines+markers',
        name=metric.title(),
        line=dict(width=2)
    ))
    fig.update_layout(
        title=f"{metric.replace('_', ' ').title()} Over Versions",
        xaxis_title="Model Version",
        yaxis_title=f"{metric.replace('_', ' ').title()} (%)",
        template="plotly_white",
        height=400
    )
    fig.write_html(os.path.join(charts_dir, f"plotly_{metric}.html"))

# Generate HTML dashboard with external template
with open(template_path, "r") as f:
    template = f.read()

table_html = df_metrics_all[["version", "accuracy", "precision_macro", "recall_macro", "f1_macro", "support"]].to_html(
    index=False, classes="table table-bordered table-striped table-hover table-sm align-middle")

with open(output_dashboard, "w") as f:
    f.write(template.replace("{table}", table_html))

logging.info("Dashboard updated with sucesso!")