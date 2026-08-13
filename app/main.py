"""Wazuh alert ingestion, incident reporting, and chat delivery service."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel, Field


class Settings(BaseModel):
    ingest_api_key: str = Field(default_factory=lambda: os.getenv("INGEST_API_KEY", ""))
    report_min_severity: int = Field(default_factory=lambda: int(os.getenv("REPORT_MIN_SEVERITY", "10")))
    discord_webhook_url: str = Field(default_factory=lambda: os.getenv("DISCORD_WEBHOOK_URL", ""))
    slack_webhook_url: str = Field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL", ""))
    llm_api_url: str = Field(default_factory=lambda: os.getenv("LLM_API_URL", ""))
    llm_api_key: str = Field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    llm_model: str = Field(default_factory=lambda: os.getenv("LLM_MODEL", "gpt-4o-mini"))
    database_path: str = Field(default_factory=lambda: os.getenv("DATABASE_PATH", "data/sidecar.db"))


settings = Settings()
app = FastAPI(title="Wazuh Incident Sidecar", version="1.0.0")


@contextmanager
def database():
    path = Path(settings.database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database() -> None:
    with database() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
              fingerprint TEXT PRIMARY KEY, alert_id TEXT, severity INTEGER NOT NULL,
              received_at TEXT NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
              id INTEGER PRIMARY KEY AUTOINCREMENT, alert_fingerprint TEXT NOT NULL,
              severity INTEGER NOT NULL, created_at TEXT NOT NULL, report TEXT NOT NULL,
              discord_status TEXT NOT NULL, slack_status TEXT NOT NULL DEFAULT 'not_configured'
            );
            """
        )
        # Existing Sidecar databases need the delivery status field added in place.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(reports)")}
        if "slack_status" not in columns:
            conn.execute("ALTER TABLE reports ADD COLUMN slack_status TEXT NOT NULL DEFAULT 'not_configured'")


@app.on_event("startup")
def startup() -> None:
    initialize_database()


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    # Empty key is allowed only for local development convenience.
    if settings.ingest_api_key and x_api_key != settings.ingest_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def get_nested(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def normalized_alert(alert: dict[str, Any]) -> tuple[str, str, int]:
    alert_id = str(alert.get("id") or "")
    severity_value = get_nested(alert, "rule", "level", default=alert.get("severity", 0))
    try:
        severity = int(severity_value)
    except (TypeError, ValueError):
        severity = 0
    canonical = json.dumps(alert, sort_keys=True, default=str, separators=(",", ":"))
    fingerprint = alert_id or hashlib.sha256(canonical.encode()).hexdigest()
    return fingerprint, alert_id, severity


def fallback_report(alert: dict[str, Any], severity: int) -> str:
    rule = get_nested(alert, "rule", "description", default="Wazuh alert")
    rule_id = get_nested(alert, "rule", "id", default="unknown")
    agent = get_nested(alert, "agent", "name", default="manager/unknown")
    source = get_nested(alert, "data", "srcip", default="not available")
    log = str(alert.get("full_log") or "No raw log provided.")[:900]
    return (
        f"## Wazuh Incident Report\n"
        f"**Severity:** {severity}/15\n"
        f"**Detection:** {rule} (rule {rule_id})\n"
        f"**Affected agent:** {agent}\n"
        f"**Source:** {source}\n\n"
        f"### Recommended triage\n"
        f"1. Validate the event on `{agent}` and preserve relevant logs.\n"
        f"2. Investigate the source and related events around the alert timestamp.\n"
        f"3. Contain affected systems if malicious activity is confirmed.\n\n"
        f"### Evidence\n```\n{log}\n```"
    )


async def generate_report(alert: dict[str, Any], severity: int) -> str:
    if not (settings.llm_api_url and settings.llm_api_key):
        return fallback_report(alert, severity)
    prompt = {
        "role": "user",
        "content": (
            "You are a SOC incident analyst. Write a concise Markdown incident report for this "
            "Wazuh alert. Include: executive summary, severity rationale, affected asset, "
            "evidence, MITRE ATT&CK techniques only when supported by evidence, and prioritized "
            "containment/validation actions. Do not invent facts.\n\n"
            + json.dumps(alert, default=str)[:12000]
        ),
    }
    headers = {"Authorization": f"Bearer {settings.llm_api_key}"}
    body = {"model": settings.llm_model, "messages": [{"role": "system", "content": "Be precise and operationally useful."}, prompt], "temperature": 0.2}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(settings.llm_api_url, headers=headers, json=body)
            response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return str(content).strip() or fallback_report(alert, severity)
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
        return fallback_report(alert, severity)


async def deliver_discord(report: str) -> str:
    if not settings.discord_webhook_url:
        return "not_configured"
    # Discord limits content to 2,000 characters. Preserve a report link/history locally for full text.
    content = report[:1900] + ("\n…(truncated; retrieve via /v1/reports)" if len(report) > 1900 else "")
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(settings.discord_webhook_url, json={"content": content})
            response.raise_for_status()
        return "sent"
    except httpx.HTTPError:
        return "failed"


def shorten_for_slack(text: str, limit: int = 2700) -> str:
    """Slack limits section text to 3,000 characters; leave space for a notice."""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 70].rstrip() + "\n\n_Additional details are available from the Sidecar API._"


def slack_markdown(text: str) -> str:
    """Convert the small Markdown subset used by reports into Slack mrkdwn."""
    text = text.replace("**", "*")
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    return shorten_for_slack(text)


def split_report_sections(report: str) -> dict[str, str]:
    """Split an LLM Markdown report into named Slack-friendly sections."""
    sections: dict[str, list[str]] = {}
    current = "Incident details"
    sections[current] = []
    for line in report.splitlines():
        heading = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if heading:
            current = heading.group(1).strip()
            sections.setdefault(current, [])
        else:
            sections[current].append(line)
    return {heading: slack_markdown("\n".join(lines)) for heading, lines in sections.items() if "\n".join(lines).strip()}


def report_section(sections: dict[str, str], *names: str) -> str:
    """Get the first matching report section without relying on exact heading case."""
    wanted = {name.casefold() for name in names}
    for heading, body in sections.items():
        if heading.casefold() in wanted:
            return body
    return ""


async def deliver_slack(alert: dict[str, Any], report: str, severity: int) -> str:
    if not settings.slack_webhook_url:
        return "not_configured"
    rule = str(get_nested(alert, "rule", "description", default="Wazuh alert"))[:160]
    rule_id = str(get_nested(alert, "rule", "id", default="unknown"))
    agent = str(get_nested(alert, "agent", "name", default="manager/unknown"))
    source = str(get_nested(alert, "data", "srcip", default="not available"))
    alert_id = str(alert.get("id") or "not available")
    timestamp = str(alert.get("timestamp") or "not available")
    sections = split_report_sections(report)
    summary = report_section(sections, "Executive Summary", "Incident details") or slack_markdown(report)
    evidence = report_section(sections, "Evidence")
    mitre = report_section(sections, "MITRE ATT&CK Techniques")
    if mitre:
        evidence = "\n\n".join(part for part in (evidence, f"*MITRE ATT&CK*\n{mitre}") if part)
    evidence = shorten_for_slack(evidence)
    actions = report_section(sections, "Prioritized Containment/Validation Actions", "Recommended triage", "Recommended Actions")
    severity_label, severity_icon = (
        ("Critical", ":red_circle:") if severity >= 13 else ("High", ":large_orange_circle:")
    )
    payload = {
        "username": "Wazuh Sidecar",
        "icon_emoji": ":shield:",
        "text": f"{severity_label} Wazuh incident: {rule}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "Security Incident • Wazuh", "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"{severity_icon} *{severity_label} severity alert — investigation required*\n{rule}"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity*\n{severity}/15 ({severity_label})"},
                    {"type": "mrkdwn", "text": f"*Affected asset*\n{agent}"},
                    {"type": "mrkdwn", "text": f"*Rule ID*\n{rule_id}"},
                    {"type": "mrkdwn", "text": f"*Source*\n{source}"},
                    {"type": "mrkdwn", "text": f"*Detected*\n{timestamp}"},
                    {"type": "mrkdwn", "text": f"*Alert ID*\n{alert_id}"},
                ],
            },
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Executive summary*\n{summary}"}},
        ],
    }
    if evidence:
        payload["blocks"].append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Key evidence*\n{evidence}"}})
    if actions:
        payload["blocks"].append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Recommended actions*\n{actions}"}})
    payload["blocks"].append({"type": "context", "elements": [{"type": "mrkdwn", "text": "Generated by Wazuh Sidecar • Validate findings before taking containment action."}]})
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(settings.slack_webhook_url, json=payload)
            response.raise_for_status()
        return "sent" if response.text.strip() == "ok" else "failed"
    except httpx.HTTPError:
        return "failed"


async def process_alert(alert: dict[str, Any]) -> dict[str, Any]:
    fingerprint, alert_id, severity = normalized_alert(alert)
    received_at = datetime.now(timezone.utc).isoformat()
    with database() as conn:
        inserted = conn.execute(
            "INSERT OR IGNORE INTO alerts(fingerprint, alert_id, severity, received_at, payload) VALUES (?, ?, ?, ?, ?)",
            (fingerprint, alert_id, severity, received_at, json.dumps(alert, default=str)),
        ).rowcount
    if not inserted:
        return {"fingerprint": fingerprint, "status": "duplicate", "severity": severity}
    if severity < settings.report_min_severity:
        return {"fingerprint": fingerprint, "status": "stored", "severity": severity}
    report = await generate_report(alert, severity)
    discord_status = await deliver_discord(report)
    slack_status = await deliver_slack(alert, report, severity)
    with database() as conn:
        report_id = conn.execute(
            "INSERT INTO reports(alert_fingerprint, severity, created_at, report, discord_status, slack_status) VALUES (?, ?, ?, ?, ?, ?)",
            (fingerprint, severity, datetime.now(timezone.utc).isoformat(), report, discord_status, slack_status),
        ).lastrowid
    return {"fingerprint": fingerprint, "status": "reported", "severity": severity, "report_id": report_id, "discord_status": discord_status, "slack_status": slack_status}


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "report_min_severity": settings.report_min_severity, "llm_configured": bool(settings.llm_api_url and settings.llm_api_key), "discord_configured": bool(settings.discord_webhook_url), "slack_configured": bool(settings.slack_webhook_url)}


@app.post("/v1/alerts", dependencies=[Depends(require_api_key)])
async def ingest_alerts(payload: dict[str, Any]) -> dict[str, Any]:
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else [payload]
    results = [await process_alert(alert) for alert in alerts if isinstance(alert, dict)]
    if not results:
        raise HTTPException(status_code=422, detail="Expected a Wazuh alert object or an alerts array")
    return {"processed": len(results), "results": results}


@app.get("/v1/alerts", dependencies=[Depends(require_api_key)])
def list_alerts(limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, Any]]:
    with database() as conn:
        rows = conn.execute("SELECT fingerprint, alert_id, severity, received_at, payload FROM alerts ORDER BY received_at DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]


@app.get("/v1/reports", dependencies=[Depends(require_api_key)])
def list_reports(limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, Any]]:
    with database() as conn:
        rows = conn.execute("SELECT * FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]
