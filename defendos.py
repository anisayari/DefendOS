#!/usr/bin/env python3

from __future__ import annotations

import argparse
import email
import fcntl
import html
import imaplib
import ipaddress
import json
import os
import re
import shutil
import smtplib
import ssl
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.header import decode_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default
from email.utils import getaddresses, parseaddr
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

DEFAULT_EXTERNAL_ENV_FILES: list[str] = []

DEFAULT_DASHBOARD_HTML = """<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DefendOS</title>
    <style>
      :root {
        --bg: #121511;
        --panel: #171c16;
        --panel-2: #212a1f;
        --text: #edf2df;
        --muted: #aab59a;
        --accent: #d1ff61;
        --accent-2: #88c057;
        --danger: #ff7663;
        --warn: #ffcb5b;
        --border: rgba(209, 255, 97, 0.12);
        --shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
      }

      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
        background:
          radial-gradient(circle at top left, rgba(209,255,97,0.12), transparent 30%),
          radial-gradient(circle at top right, rgba(90,130,65,0.18), transparent 26%),
          linear-gradient(180deg, #10130f 0%, #151a14 100%);
        color: var(--text);
        min-height: 100vh;
      }

      .wrap {
        max-width: 1280px;
        margin: 0 auto;
        padding: 28px 20px 56px;
      }

      .hero {
        display: grid;
        grid-template-columns: 1.4fr 1fr;
        gap: 18px;
        margin-bottom: 18px;
      }

      .card {
        background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.0)), var(--panel);
        border: 1px solid var(--border);
        border-radius: 18px;
        box-shadow: var(--shadow);
        padding: 18px;
      }

      .eyebrow {
        font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--accent);
        margin-bottom: 10px;
      }

      h1, h2, h3 {
        margin: 0;
        font-weight: 700;
      }

      h1 {
        font-size: clamp(34px, 5vw, 56px);
        line-height: 0.94;
        letter-spacing: -0.04em;
        max-width: 12ch;
      }

      .lede {
        color: var(--muted);
        font-size: 16px;
        line-height: 1.65;
        margin-top: 14px;
        max-width: 58ch;
      }

      .stats {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 12px;
        margin-top: 18px;
      }

      .stat {
        padding: 14px;
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 14px;
        background: rgba(255,255,255,0.02);
      }

      .stat-label {
        color: var(--muted);
        font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.1em;
      }

      .stat-value {
        font-size: 28px;
        line-height: 1.1;
        margin-top: 8px;
      }

      .severity {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        border-radius: 999px;
        padding: 8px 12px;
        font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }

      .severity.info, .severity.low {
        background: rgba(136,192,87,0.16);
        color: #d8ff98;
      }

      .severity.medium {
        background: rgba(255,203,91,0.16);
        color: #ffe28f;
      }

      .severity.high, .severity.critical {
        background: rgba(255,118,99,0.18);
        color: #ffb7ac;
      }

      .controls {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 16px;
      }

      button, .ghost-input, textarea {
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.08);
        background: rgba(255,255,255,0.04);
        color: var(--text);
        font: inherit;
      }

      button {
        cursor: pointer;
        padding: 12px 14px;
        font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }

      button.primary {
        background: var(--accent);
        color: #18200b;
        border-color: rgba(0,0,0,0.06);
      }

      button:hover {
        transform: translateY(-1px);
      }

      .grid {
        display: grid;
        grid-template-columns: 1.1fr 1fr;
        gap: 18px;
      }

      .list, .meta {
        display: grid;
        gap: 10px;
      }

      .row {
        padding: 12px 14px;
        border-radius: 14px;
        background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.05);
      }

      .row-top {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
      }

      .mono {
        font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      }

      .muted {
        color: var(--muted);
      }

      .pill-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }

      .pill {
        border-radius: 999px;
        padding: 7px 10px;
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.06);
        font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
      }

      textarea {
        width: 100%;
        min-height: 120px;
        padding: 14px;
        resize: vertical;
      }

      .log {
        white-space: pre-wrap;
        font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        color: #d7e2c3;
      }

      a {
        color: var(--accent);
      }

      @media (max-width: 980px) {
        .hero, .grid {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div class="wrap">
      <section class="hero">
        <div class="card">
          <div class="eyebrow">DefendOS // Global Surveillance</div>
          <h1>Vue d'ensemble du VPS</h1>
          <p class="lede">Suivi des runs de surveillance, de l'analyse Codex, des alertes email et des commandes reçues sur la mailbox DefendOS.</p>
          <div class="stats">
            <div class="stat">
              <div class="stat-label">Dernière sévérité</div>
              <div class="stat-value" id="latestSeverityValue">-</div>
            </div>
            <div class="stat">
              <div class="stat-label">Dernier run</div>
              <div class="stat-value" id="latestRunValue">-</div>
            </div>
            <div class="stat">
              <div class="stat-label">Codex</div>
              <div class="stat-value" id="codexReadyValue">-</div>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="eyebrow">Actions</div>
          <div id="latestSeverityBadge" class="severity info">chargement</div>
          <div class="controls">
            <button class="primary" onclick="triggerAction('/api/actions/healthcheck', {})">Run Healthcheck</button>
            <button onclick="triggerAction('/api/actions/poll-inbox', {})">Poll Inbox</button>
            <button onclick="triggerAction('/api/actions/self-test', {})">Self Test</button>
          </div>
          <div style="margin-top:16px;">
            <textarea id="manualRequest" placeholder="Demande manuelle pour Codex. Exemple: verifie les connexions root et le port 5905."></textarea>
            <div class="controls">
              <button onclick="manualInvestigate()">Lancer enquête</button>
            </div>
          </div>
          <div id="actionResult" class="log muted" style="margin-top:14px;"></div>
        </div>
      </section>

      <section class="grid">
        <div class="card">
          <div class="eyebrow">Derniers Runs</div>
          <div id="runs" class="list"></div>
        </div>
        <div class="card">
          <div class="eyebrow">Configuration Active</div>
          <div id="config" class="meta"></div>
        </div>
      </section>

      <section class="grid" style="margin-top:18px;">
        <div class="card">
          <div class="eyebrow">Derniers Événements</div>
          <div id="events" class="list"></div>
        </div>
        <div class="card">
          <div class="eyebrow">Détails Dernier Run</div>
          <div id="latestDetail" class="list"></div>
        </div>
      </section>
    </div>

    <script>
      function escapeHtml(value) {
        return String(value ?? "").replace(/[&<>"]/g, function (c) {
          return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c];
        });
      }

      function severityClass(severity) {
        return ["info", "low", "medium", "high", "critical"].includes(severity) ? severity : "info";
      }

      function renderRuns(runs) {
        const root = document.getElementById("runs");
        if (!runs.length) {
          root.innerHTML = '<div class="row muted">Aucun run disponible.</div>';
          return;
        }
        root.innerHTML = runs.map((run) => {
          const result = run.final_result || {};
          return `
            <div class="row">
              <div class="row-top">
                <strong>${escapeHtml(run.trigger_kind || "run")}</strong>
                <span class="severity ${severityClass(result.severity)}">${escapeHtml(result.severity || "info")}</span>
              </div>
              <div class="muted" style="margin-top:8px;">${escapeHtml(run.generated_at || "")}</div>
              <div style="margin-top:10px;">${escapeHtml(result.summary || "Sans résumé")}</div>
              <div class="mono muted" style="margin-top:10px;">${escapeHtml(run.run_dir || "")}</div>
            </div>
          `;
        }).join("");
      }

      function renderConfig(config) {
        const root = document.getElementById("config");
        const pills = [
          ["Email", config.email_provider],
          ["Inbox", config.inbox_provider],
          ["Codex", config.codex_ready ? "ready" : "missing"],
          ["Resend", config.resend_ready ? "ready" : "missing"],
          ["Dashboard", config.dashboard_bind],
        ];
        root.innerHTML = `
          <div class="pill-row">${pills.map(([label, value]) => `<div class="pill">${escapeHtml(label)}: ${escapeHtml(value)}</div>`).join("")}</div>
          <div class="row">
            <div class="row-top"><strong>Alertes</strong></div>
            <div class="muted" style="margin-top:8px;">Destinataire: ${escapeHtml(config.alert_email_to || "non defini")}</div>
            <div class="muted">Inbox: ${escapeHtml(config.inbox_address || "non definie")}</div>
            <div class="muted">Allowed senders: ${escapeHtml((config.allowed_senders || []).join(", ") || "none")}</div>
          </div>
          <div class="row">
            <div class="row-top"><strong>Surface attendue</strong></div>
            <div class="muted" style="margin-top:8px;">Ports publics: ${escapeHtml((config.expected_public_ports || []).join(", "))}</div>
            <div class="muted">IPs de confiance: ${escapeHtml((config.trusted_login_ips || []).join(", ") || "none")}</div>
          </div>
        `;
      }

      function renderEvents(events) {
        const root = document.getElementById("events");
        if (!events.length) {
          root.innerHTML = '<div class="row muted">Aucun événement.</div>';
          return;
        }
        root.innerHTML = events.map((event) => `
          <div class="row">
            <div class="row-top">
              <strong>${escapeHtml(event.type || "event")}</strong>
              <span class="mono muted">${escapeHtml(event.timestamp || "")}</span>
            </div>
            <div class="log" style="margin-top:10px;">${escapeHtml(JSON.stringify(event, null, 2))}</div>
          </div>
        `).join("");
      }

      function renderLatestDetail(run) {
        const root = document.getElementById("latestDetail");
        if (!run) {
          root.innerHTML = '<div class="row muted">Aucun détail disponible.</div>';
          return;
        }
        const result = run.final_result || {};
        const findings = (result.findings || []).map((item) => `<div class="pill">${escapeHtml(item)}</div>`).join("");
        const actions = (result.recommended_actions || []).map((item) => `<div class="pill">${escapeHtml(item)}</div>`).join("");
        root.innerHTML = `
          <div class="row">
            <div class="row-top">
              <strong>${escapeHtml(result.summary || "Sans résumé")}</strong>
              <span class="severity ${severityClass(result.severity)}">${escapeHtml(result.severity || "info")}</span>
            </div>
            <div class="muted" style="margin-top:8px;">${escapeHtml(run.generated_at || "")}</div>
          </div>
          <div class="row">
            <strong>Constats</strong>
            <div class="pill-row" style="margin-top:10px;">${findings || '<div class="muted">Aucun constat</div>'}</div>
          </div>
          <div class="row">
            <strong>Actions</strong>
            <div class="pill-row" style="margin-top:10px;">${actions || '<div class="muted">Aucune action</div>'}</div>
          </div>
          <div class="row">
            <strong>Répertoire</strong>
            <div class="mono muted" style="margin-top:8px;">${escapeHtml(run.run_dir || "")}</div>
          </div>
        `;
      }

      async function fetchStatus() {
        const response = await fetch('/api/status', { cache: 'no-store' });
        const payload = await response.json();
        const latest = payload.latest_run;
        const latestResult = latest?.final_result || {};
        document.getElementById('latestSeverityValue').textContent = latestResult.severity || '-';
        document.getElementById('latestRunValue').textContent = latest ? new Date(latest.generated_at).toLocaleTimeString('fr-FR') : '-';
        document.getElementById('codexReadyValue').textContent = payload.config.codex_ready ? 'ready' : 'missing';
        const badge = document.getElementById('latestSeverityBadge');
        badge.className = 'severity ' + severityClass(latestResult.severity || 'info');
        badge.textContent = latestResult.severity || 'info';
        renderRuns(payload.recent_runs || []);
        renderConfig(payload.config || {});
        renderEvents(payload.events || []);
        renderLatestDetail(latest);
      }

      async function triggerAction(path, payload) {
        const result = document.getElementById('actionResult');
        result.textContent = 'Execution en cours...';
        try {
          const response = await fetch(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload || {}),
          });
          const body = await response.json();
          result.textContent = JSON.stringify(body, null, 2);
          setTimeout(fetchStatus, 1500);
        } catch (error) {
          result.textContent = String(error);
        }
      }

      function manualInvestigate() {
        const request = document.getElementById('manualRequest').value.trim();
        triggerAction('/api/actions/investigate', { request });
      }

      fetchStatus();
      setInterval(fetchStatus, 10000);
    </script>
  </body>
</html>
"""


@dataclass
class Config:
    base_dir: Path
    env_path: Path
    external_env_files: list[Path]
    state_dir: Path
    runs_dir: Path
    locks_dir: Path
    jobs_dir: Path
    events_log_path: Path
    processed_messages_path: Path
    last_alert_path: Path
    inbox_state_path: Path
    healthcheck_script: Path
    schema_path: Path
    dashboard_html_path: Path
    expected_public_ports: list[str]
    trusted_login_ips: list[str]
    alert_email_to: str | None
    inbox_address: str | None
    allowed_senders: list[str]
    email_trigger_prefix: str
    alert_min_severity: str
    alert_suppress_minutes: int
    codex_bin: str
    codex_model: str | None
    codex_timeout_seconds: int
    codex_scheduled_timeout_seconds: int
    codex_sandbox: str
    codex_enabled: bool
    openai_api_key: str | None
    email_provider: str
    inbox_provider: str
    resend_api_key: str | None
    resend_api_base: str
    resend_from_email: str | None
    resend_reply_to_email: str | None
    resend_test_from_email: str | None
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password: str | None
    smtp_from: str | None
    smtp_use_ssl: bool
    smtp_use_starttls: bool
    imap_host: str | None
    imap_port: int
    imap_username: str | None
    imap_password: str | None
    imap_folder: str
    max_inbox_messages: int
    dashboard_host: str
    dashboard_port: int


@dataclass
class InboundMessage:
    provider: str
    unique_id: str
    source_id: str
    message_id: str
    subject: str
    sender_email: str
    sender_display: str
    recipients: list[str]
    references: str | None
    in_reply_to: str | None
    body: str
    created_at: str | None
    raw: dict[str, Any]


def load_env_file(path: Path, *, override: bool = False) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if override or key not in os.environ:
            os.environ[key] = value


def parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(value, 0)


def max_severity(left: str, right: str) -> str:
    return left if severity_rank(left) >= severity_rank(right) else right


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_text() -> str:
    return utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    return cleaned.strip("-") or "run"


def path_or_default(raw_value: str | None, default_path: Path) -> Path:
    if not raw_value:
        return default_path
    return Path(raw_value).expanduser()


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(content, encoding="utf-8")
    temp_path.replace(path)


def write_json(path: Path, payload: Any) -> None:
    write_text(path, json.dumps(payload, indent=2, ensure_ascii=True) + "\n")


def read_json(path: Path, default_value: Any) -> Any:
    if not path.exists():
        return default_value
    return json.loads(path.read_text(encoding="utf-8"))


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")


def read_jsonl_tail(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    items: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            items.append(parsed)
    return items


def decode_mime_header(value: str | None) -> str:
    if not value:
        return ""

    parts: list[str] = []
    for chunk, encoding in decode_header(value):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(encoding or "utf-8", errors="replace"))
        else:
            parts.append(chunk)
    return "".join(parts)


def strip_html(value: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</p>", "\n\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_message_text(message: email.message.EmailMessage) -> str:
    text_parts: list[str] = []
    html_parts: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            content_type = part.get_content_type()
            try:
                payload = part.get_content()
            except Exception:
                payload = ""
            if not isinstance(payload, str):
                continue
            if content_type == "text/plain":
                text_parts.append(payload)
            elif content_type == "text/html":
                html_parts.append(payload)
    else:
        try:
            payload = message.get_content()
        except Exception:
            payload = ""
        if isinstance(payload, str):
            if message.get_content_type() == "text/html":
                html_parts.append(payload)
            else:
                text_parts.append(payload)

    if text_parts:
        text = "\n\n".join(part.strip() for part in text_parts if part.strip())
        return re.sub(r"\n{3,}", "\n\n", text).strip()

    if html_parts:
        return strip_html("\n\n".join(html_parts))

    return ""


def parse_address(value: str | None) -> str | None:
    _, address = parseaddr(value or "")
    address = address.strip().lower()
    return address or None


def header_lookup(headers: dict[str, Any] | None, name: str) -> str | None:
    if not headers:
        return None
    name_lower = name.lower()
    for key, value in headers.items():
        if key.lower() == name_lower and value is not None:
            return str(value)
    return None


def load_external_env_files(base_dir: Path, env_path: Path) -> list[Path]:
    load_env_file(env_path)
    candidates = parse_csv(os.environ.get("DEFENDOS_EXTERNAL_ENV_FILES"))
    if not candidates:
        candidates = DEFAULT_EXTERNAL_ENV_FILES
    paths = [Path(item).expanduser() for item in candidates]
    for path in paths:
        load_env_file(path)
    return paths


def build_config() -> Config:
    base_dir = Path(__file__).resolve().parent
    env_path = base_dir / "defendos.env"
    external_env_files = load_external_env_files(base_dir, env_path)

    state_dir = base_dir / "state"
    runs_dir = state_dir / "runs"
    locks_dir = state_dir / "locks"
    jobs_dir = state_dir / "jobs"

    resend_from_email = (
        os.environ.get("DEFENDOS_RESEND_FROM_EMAIL")
        or (f"DefendOS <{os.environ.get('DEFENDOS_INBOX_ADDRESS')}>" if os.environ.get("DEFENDOS_INBOX_ADDRESS") else None)
        or os.environ.get("RESEND_FROM_EMAIL")
        or "DefendOS <defendos@example.com>"
    )

    admin_allowed_email = os.environ.get("ADMIN_ALLOWED_EMAIL") or None
    discovered_from_address = os.environ.get("RESEND_FROM_EMAIL") or resend_from_email
    allowed_senders = parse_csv(os.environ.get("DEFENDOS_ALLOWED_SENDERS"))
    if not allowed_senders:
        if admin_allowed_email:
            allowed_senders.append(admin_allowed_email)
        discovered_sender = parse_address(discovered_from_address)
        if discovered_sender:
            allowed_senders.append(discovered_sender)

    expected_public_ports = parse_csv(os.environ.get("DEFENDOS_EXPECTED_PUBLIC_PORTS")) or ["22", "80", "443"]
    codex_timeout_seconds = int(os.environ.get("DEFENDOS_CODEX_TIMEOUT_SECONDS") or "900")
    codex_scheduled_timeout_seconds = int(
        os.environ.get("DEFENDOS_CODEX_SCHEDULED_TIMEOUT_SECONDS") or str(min(codex_timeout_seconds, 180))
    )

    return Config(
        base_dir=base_dir,
        env_path=env_path,
        external_env_files=external_env_files,
        state_dir=state_dir,
        runs_dir=runs_dir,
        locks_dir=locks_dir,
        jobs_dir=jobs_dir,
        events_log_path=state_dir / "events.jsonl",
        processed_messages_path=state_dir / "processed_message_ids.json",
        last_alert_path=state_dir / "last_alert.json",
        inbox_state_path=state_dir / "inbox_state.json",
        healthcheck_script=path_or_default(
            os.environ.get("DEFENDOS_HEALTHCHECK_SCRIPT"),
            base_dir / "healthcheck.sh",
        ),
        schema_path=base_dir / "codex_output.schema.json",
        dashboard_html_path=base_dir / "dashboard.html",
        expected_public_ports=expected_public_ports,
        trusted_login_ips=parse_csv(os.environ.get("DEFENDOS_TRUSTED_LOGIN_IPS")),
        alert_email_to=(os.environ.get("DEFENDOS_ALERT_EMAIL_TO") or admin_allowed_email or "").strip() or None,
        inbox_address=(os.environ.get("DEFENDOS_INBOX_ADDRESS") or "defendos@example.com").strip().lower() or None,
        allowed_senders=sorted(set(item.strip().lower() for item in allowed_senders if item.strip())),
        email_trigger_prefix=(os.environ.get("DEFENDOS_EMAIL_TRIGGER_PREFIX") or "defendos:").strip().lower(),
        alert_min_severity=(os.environ.get("DEFENDOS_ALERT_MIN_SEVERITY") or "high").strip().lower(),
        alert_suppress_minutes=int(os.environ.get("DEFENDOS_ALERT_SUPPRESS_MINUTES") or "120"),
        codex_bin=os.environ.get("CODEX_BIN") or os.environ.get("DEFENDOS_CODEX_BIN") or "codex",
        codex_model=(
            (os.environ.get("DEFENDOS_CODEX_MODEL") or "").strip()
            or (os.environ.get("OPENAI_EDITOR_CODEX_MODEL") or "").strip()
            or None
        ),
        codex_timeout_seconds=codex_timeout_seconds,
        codex_scheduled_timeout_seconds=codex_scheduled_timeout_seconds,
        codex_sandbox=(os.environ.get("DEFENDOS_CODEX_SANDBOX") or "read-only").strip(),
        codex_enabled=parse_bool(os.environ.get("DEFENDOS_CODEX_ENABLED"), True),
        openai_api_key=(os.environ.get("OPENAI_API_KEY") or "").strip() or None,
        email_provider=(os.environ.get("DEFENDOS_EMAIL_PROVIDER") or ("resend" if os.environ.get("RESEND_API_KEY") else "smtp")).strip().lower(),
        inbox_provider=(os.environ.get("DEFENDOS_INBOX_PROVIDER") or ("resend" if os.environ.get("RESEND_API_KEY") else "imap")).strip().lower(),
        resend_api_key=(os.environ.get("RESEND_API_KEY") or "").strip() or None,
        resend_api_base=(os.environ.get("DEFENDOS_RESEND_API_BASE") or "https://api.resend.com").rstrip("/"),
        resend_from_email=resend_from_email,
        resend_reply_to_email=(os.environ.get("DEFENDOS_RESEND_REPLY_TO_EMAIL") or os.environ.get("RESEND_REPLY_TO_EMAIL") or "").strip() or None,
        resend_test_from_email=(os.environ.get("DEFENDOS_RESEND_TEST_FROM_EMAIL") or discovered_from_address or "").strip() or None,
        smtp_host=(os.environ.get("DEFENDOS_SMTP_HOST") or "").strip() or None,
        smtp_port=int(os.environ.get("DEFENDOS_SMTP_PORT") or "465"),
        smtp_username=(os.environ.get("DEFENDOS_SMTP_USERNAME") or "").strip() or None,
        smtp_password=(os.environ.get("DEFENDOS_SMTP_PASSWORD") or "").strip() or None,
        smtp_from=(os.environ.get("DEFENDOS_SMTP_FROM") or "").strip() or None,
        smtp_use_ssl=parse_bool(os.environ.get("DEFENDOS_SMTP_USE_SSL"), True),
        smtp_use_starttls=parse_bool(os.environ.get("DEFENDOS_SMTP_USE_STARTTLS"), False),
        imap_host=(os.environ.get("DEFENDOS_IMAP_HOST") or "").strip() or None,
        imap_port=int(os.environ.get("DEFENDOS_IMAP_PORT") or "993"),
        imap_username=(os.environ.get("DEFENDOS_IMAP_USERNAME") or "").strip() or None,
        imap_password=(os.environ.get("DEFENDOS_IMAP_PASSWORD") or "").strip() or None,
        imap_folder=os.environ.get("DEFENDOS_IMAP_FOLDER") or "INBOX",
        max_inbox_messages=int(os.environ.get("DEFENDOS_MAX_INBOX_MESSAGES") or "10"),
        dashboard_host=os.environ.get("DEFENDOS_DASHBOARD_HOST") or "127.0.0.1",
        dashboard_port=int(os.environ.get("DEFENDOS_DASHBOARD_PORT") or "8787"),
    )


class FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.handle: Any | None = None

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("w", encoding="utf-8")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(f"Another DefendOS process is already running for {self.path.name}")
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()


def append_event(config: Config, event_type: str, payload: dict[str, Any]) -> None:
    append_jsonl(
        config.events_log_path,
        {
            "timestamp": utc_now().isoformat(),
            "type": event_type,
            **payload,
        },
    )


def create_run_dir(config: Config, prefix: str) -> Path:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    run_dir = config.runs_dir / f"{timestamp}-{slugify(prefix)}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def run_command(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def build_subprocess_env(config: Config) -> dict[str, str]:
    env = os.environ.copy()
    if config.openai_api_key:
        env["OPENAI_API_KEY"] = config.openai_api_key
    if config.resend_api_key:
        env["RESEND_API_KEY"] = config.resend_api_key
    env.pop("CODEX_SANDBOX_NETWORK_DISABLED", None)
    env["PYTHONUNBUFFERED"] = "1"
    return env


def run_healthcheck(config: Config, run_dir: Path) -> dict[str, Any]:
    env = build_subprocess_env(config)
    env["EXPECTED_PUBLIC_PORTS"] = " ".join(config.expected_public_ports)
    completed = run_command(
        ["bash", str(config.healthcheck_script)],
        env=env,
        timeout=600,
        cwd=run_dir,
    )
    report = completed.stdout
    if completed.stderr:
        report = f"{report}\n\n[stderr]\n{completed.stderr}".strip()
    write_text(run_dir / "healthcheck.txt", report + "\n")
    return {
        "exit_code": completed.returncode,
        "report": report,
    }


def parse_ips_from_lines(lines: list[str]) -> list[str]:
    ips: list[str] = []
    for line in lines:
        ips.extend(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line))
    return sorted(set(ips))


def is_trusted_ip(ip_text: str, trusted_entries: list[str]) -> bool:
    if not trusted_entries:
        return False

    try:
        ip_value = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    for entry in trusted_entries:
        try:
            if "/" in entry:
                if ip_value in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if ip_value == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def heuristic_analysis(report: str, config: Config) -> dict[str, Any]:
    severity = "info"
    findings: list[str] = []
    actions: list[str] = []
    warn_lines = [line for line in report.splitlines() if line.startswith("[WARN]")]
    alert_lines = [line for line in report.splitlines() if line.startswith("[ALERT]")]

    if warn_lines:
        severity = max_severity(severity, "medium")

    if alert_lines:
        severity = max_severity(severity, "high")

    if "SSH root login is enabled" in report:
        findings.append("SSH root login is enabled.")
        actions.append("Disable SSH root login as soon as possible.")
        severity = max_severity(severity, "high")

    if "SSH password authentication is enabled" in report:
        findings.append("SSH password authentication is enabled.")
        actions.append("Disable SSH password authentication and move to key-only access.")
        severity = max_severity(severity, "high")

    unexpected_ports = re.findall(r"Unexpected public port listening: (\d+)", report)
    if unexpected_ports:
        findings.append(
            "Unexpected public ports are listening: " + ", ".join(sorted(set(unexpected_ports))) + "."
        )
        actions.append("Review the unexpected public ports and close what is not required.")
        severity = max_severity(severity, "medium")

    root_login_lines = [
        line
        for line in report.splitlines()
        if "Accepted password for root" in line
    ]
    if root_login_lines:
        root_login_ips = parse_ips_from_lines(root_login_lines)
        untrusted_root_ips = [ip for ip in root_login_ips if not is_trusted_ip(ip, config.trusted_login_ips)]
        findings.append(
            "Recent root password logins were accepted from: " + ", ".join(root_login_ips) + "."
        )
        actions.append("Verify every root login source IP and rotate the root password if any IP is unknown.")
        if untrusted_root_ips:
            findings.append(
                "Untrusted root password login IPs detected: " + ", ".join(untrusted_root_ips) + "."
            )
            actions.append("Treat the host as potentially compromised until those IPs are verified.")
            severity = max_severity(severity, "critical")
        else:
            severity = max_severity(severity, "high")

    if "Recent SSH brute-force activity detected" in report:
        findings.append("Recent SSH brute-force activity was detected in auth logs.")
        actions.append("Keep fail2ban enabled and review whether SSH should be restricted to trusted IPs.")
        severity = max_severity(severity, "medium")

    if "ufw is not active" in report:
        findings.append("UFW is not active.")
        actions.append("Enable a deny-by-default firewall policy before exposing more services.")
        severity = max_severity(severity, "critical")

    if "Multiple root sessions are currently open" in report:
        findings.append("Multiple root sessions are open right now.")
        actions.append("Verify every current root session and close what is not expected.")
        severity = max_severity(severity, "high")

    if not findings:
        findings.append("No major issue was detected by the heuristic checks.")

    summary = findings[0]
    send_email = severity_rank(severity) >= severity_rank(config.alert_min_severity)

    return {
        "severity": severity,
        "summary": summary,
        "findings": findings,
        "recommended_actions": actions,
        "send_email": send_email,
        "urgent": severity in {"high", "critical"},
    }


def build_codex_prompt(
    config: Config,
    *,
    trigger_kind: str,
    operator_request: str | None,
    heuristic: dict[str, Any],
) -> str:
    request_text = operator_request.strip() if operator_request else "No direct operator request. This is a scheduled healthcheck."
    trusted_ip_text = ", ".join(config.trusted_login_ips) if config.trusted_login_ips else "none configured"
    port_text = ", ".join(config.expected_public_ports)

    return textwrap.dedent(
        f"""
        You are DefendOS, a Linux VPS security triage agent.
        Current time: {utc_now_text()}.

        Your job is to investigate this machine in READ ONLY mode.
        You may read files and run safe inspection commands.
        You must NOT modify files, install packages, restart services, kill processes, edit configs, or change firewall rules.

        Start by reading these files from the current working directory:
        - healthcheck.txt
        - context.json

        Then investigate the host if needed using safe commands.
        Focus on:
        - SSH abuse, especially accepted root password logins
        - unexpected public ports
        - suspicious persistence via cron, systemd, shell profiles, SSH keys
        - auth log anomalies
        - suspicious processes
        - any concrete sign of compromise

        Configuration context:
        - Trusted login IPs: {trusted_ip_text}
        - Expected public ports: {port_text}
        - Trigger kind: {trigger_kind}
        - Operator request: {request_text}

        Heuristic pre-analysis:
        - Severity: {heuristic["severity"]}
        - Summary: {heuristic["summary"]}
        - Findings: {" | ".join(heuristic["findings"])}

        Return ONLY JSON matching the provided schema.
        Reply in French.
        Keep the reply concise and operational.
        """
    ).strip()


def resolve_codex_bin(config: Config) -> str | None:
    if "/" in config.codex_bin:
        return config.codex_bin if Path(config.codex_bin).exists() else None
    return shutil.which(config.codex_bin)


def run_codex_investigation(
    config: Config,
    *,
    run_dir: Path,
    prompt: str,
    timeout_seconds: int,
) -> dict[str, Any] | None:
    codex_bin = resolve_codex_bin(config)
    if not codex_bin:
        return None

    output_path = run_dir / "codex-last-message.json"
    command = [
        codex_bin,
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "--sandbox",
        config.codex_sandbox,
        "-C",
        str(run_dir),
        "--output-schema",
        str(config.schema_path),
        "-o",
        str(output_path),
        "-c",
        'sandbox_permissions=["disk-full-read-access"]',
    ]

    if config.codex_model:
        command.extend(["-m", config.codex_model])

    command.append(prompt)

    started_at = time.time()
    try:
        completed = run_command(
            command,
            env=build_subprocess_env(config),
            cwd=run_dir,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        write_text(run_dir / "codex-stderr.log", f"Codex timed out after {timeout_seconds}s\n{error}\n")
        return {
            "severity": "high",
            "urgent": True,
            "send_email": True,
            "summary": "Codex a expire avant de terminer l'enquete.",
            "findings": ["Codex n'a pas reussi a finir l'analyse dans le temps imparti."],
            "recommended_actions": ["Relance l'analyse manuellement et verifie l'etat du serveur sans attendre."],
            "needs_user_reply": True,
            "reply_subject": "[DefendOS] Codex timeout",
            "reply_body": f"Codex a expire apres {timeout_seconds} secondes. Relance une verification manuelle du serveur.",
            "codex_runtime_seconds": round(time.time() - started_at, 2),
        }

    write_text(run_dir / "codex-stdout.log", completed.stdout)
    write_text(run_dir / "codex-stderr.log", completed.stderr)

    if not output_path.exists():
        return None

    try:
        payload = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

    payload["codex_exit_code"] = completed.returncode
    payload["codex_runtime_seconds"] = round(time.time() - started_at, 2)
    return payload


def run_codex_smoke_test(config: Config) -> dict[str, Any]:
    codex_bin = resolve_codex_bin(config)
    if not codex_bin:
        raise RuntimeError("Codex binary not found")
    if not config.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is missing")

    output_path = config.state_dir / "codex-smoke-last-message.txt"
    stdout_path = config.state_dir / "codex-smoke-stdout.log"
    stderr_path = config.state_dir / "codex-smoke-stderr.log"
    command = [
        codex_bin,
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "-C",
        str(config.base_dir),
        "-o",
        str(output_path),
    ]
    if config.codex_model:
        command.extend(["-m", config.codex_model])
    command.append("Reply with exactly OK and no other text.")

    started_at = time.time()
    completed = run_command(
        command,
        env=build_subprocess_env(config),
        cwd=config.base_dir,
        timeout=min(config.codex_timeout_seconds, 180),
    )
    write_text(stdout_path, completed.stdout)
    write_text(stderr_path, completed.stderr)

    if not output_path.exists():
        raise RuntimeError("Codex smoke test produced no output file")

    message = output_path.read_text(encoding="utf-8", errors="replace").strip()
    result = {
        "ok": completed.returncode == 0 and message == "OK",
        "exit_code": completed.returncode,
        "message": message,
        "runtime_seconds": round(time.time() - started_at, 2),
    }
    append_event(config, "codex_smoke_test", result)
    return result


def codex_timeout_for_trigger(config: Config, trigger_kind: str) -> int:
    if trigger_kind == "scheduled-healthcheck":
        return min(config.codex_timeout_seconds, config.codex_scheduled_timeout_seconds)
    return config.codex_timeout_seconds


def compose_html_email(subject: str, body: str) -> str:
    paragraphs = "".join(
        f"<p style='margin:0 0 14px;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:26px;color:#111'>{html.escape(block).replace(chr(10), '<br />')}</p>"
        for block in body.strip().split("\n\n")
        if block.strip()
    )
    return (
        "<!doctype html><html><body style='margin:0;padding:24px;background:#f3f5ef;'>"
        "<div style='max-width:720px;margin:0 auto;padding:24px;background:#ffffff;border:1px solid #dfe8c8;'>"
        f"<h1 style='font-family:Arial,Helvetica,sans-serif;font-size:22px;line-height:30px;color:#111;margin:0 0 18px;'>{html.escape(subject)}</h1>"
        f"{paragraphs}"
        "</div></body></html>"
    )


def resend_request(
    config: Config,
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not config.resend_api_key:
        raise RuntimeError("Resend is not configured")

    query = urlencode({key: value for key, value in (params or {}).items() if value is not None})
    url = f"{config.resend_api_base}{path}"
    if query:
        url = f"{url}?{query}"

    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {config.resend_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "DefendOS/1.0",
        },
    )

    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Resend API error ({method} {path}): {raw or error.reason}")
    except URLError as error:
        raise RuntimeError(f"Resend API unreachable: {error}")


def send_email_via_resend(
    config: Config,
    *,
    to_address: str,
    subject: str,
    body: str,
    in_reply_to: str | None = None,
    references: str | None = None,
    from_override: str | None = None,
) -> dict[str, Any]:
    from_address = (from_override or config.resend_from_email or config.smtp_from or "").strip()
    if not from_address:
        raise RuntimeError("No from address configured for Resend")

    headers: dict[str, str] = {}
    if in_reply_to:
        headers["In-Reply-To"] = in_reply_to
    if references:
        headers["References"] = references

    payload: dict[str, Any] = {
        "from": from_address,
        "to": [to_address],
        "subject": subject,
        "text": body,
        "html": compose_html_email(subject, body),
    }
    if config.resend_reply_to_email:
        payload["reply_to"] = config.resend_reply_to_email
    if headers:
        payload["headers"] = headers

    response = resend_request(config, "POST", "/emails", payload=payload)
    result = {
        "provider": "resend",
        "to": to_address,
        "subject": subject,
        "id": response.get("id"),
        "from": from_address,
    }
    append_event(config, "email_sent", result)
    return result


def send_email_via_smtp(
    config: Config,
    *,
    to_address: str,
    subject: str,
    body: str,
    in_reply_to: str | None = None,
    references: str | None = None,
) -> dict[str, Any]:
    if not config.smtp_host or not config.smtp_username or not config.smtp_password:
        raise RuntimeError("SMTP is not fully configured")

    from_address = config.smtp_from or config.inbox_address or config.smtp_username
    message = EmailMessage()
    message["From"] = from_address
    message["To"] = to_address
    message["Subject"] = subject
    if in_reply_to:
        message["In-Reply-To"] = in_reply_to
    if references:
        message["References"] = references
    message.set_content(body)
    message.add_alternative(compose_html_email(subject, body), subtype="html")

    if config.smtp_use_ssl:
        with smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, context=ssl.create_default_context()) as server:
            server.login(config.smtp_username, config.smtp_password)
            server.send_message(message)
    else:
        with smtplib.SMTP(config.smtp_host, config.smtp_port) as server:
            if config.smtp_use_starttls:
                server.starttls(context=ssl.create_default_context())
            server.login(config.smtp_username, config.smtp_password)
            server.send_message(message)

    result = {
        "provider": "smtp",
        "to": to_address,
        "subject": subject,
        "from": from_address,
    }
    append_event(config, "email_sent", result)
    return result


def send_email(
    config: Config,
    *,
    to_address: str,
    subject: str,
    body: str,
    in_reply_to: str | None = None,
    references: str | None = None,
    from_override: str | None = None,
) -> dict[str, Any]:
    if config.email_provider == "resend":
        return send_email_via_resend(
            config,
            to_address=to_address,
            subject=subject,
            body=body,
            in_reply_to=in_reply_to,
            references=references,
            from_override=from_override,
        )
    return send_email_via_smtp(
        config,
        to_address=to_address,
        subject=subject,
        body=body,
        in_reply_to=in_reply_to,
        references=references,
    )


def should_suppress_alert(config: Config, fingerprint: str) -> bool:
    payload = read_json(config.last_alert_path, {})
    if payload.get("fingerprint") != fingerprint:
        return False

    sent_at = payload.get("sent_at")
    if not sent_at:
        return False

    try:
        sent_time = datetime.fromisoformat(sent_at)
    except ValueError:
        return False

    delta_seconds = (utc_now() - sent_time).total_seconds()
    return delta_seconds < config.alert_suppress_minutes * 60


def remember_alert(config: Config, fingerprint: str) -> None:
    write_json(
        config.last_alert_path,
        {
            "fingerprint": fingerprint,
            "sent_at": utc_now().isoformat(),
        },
    )


def load_processed_message_ids(config: Config) -> set[str]:
    data = read_json(config.processed_messages_path, [])
    return set(item for item in data if isinstance(item, str))


def save_processed_message_ids(config: Config, message_ids: set[str]) -> None:
    write_json(config.processed_messages_path, sorted(message_ids))


def sender_is_allowed(config: Config, sender_email: str) -> bool:
    sender_email = sender_email.strip().lower()
    for entry in config.allowed_senders:
        candidate = entry.strip().lower()
        if not candidate:
            continue
        if candidate.startswith("@") and sender_email.endswith(candidate):
            return True
        if sender_email == candidate:
            return True
    return False


def email_is_addressed_to_defendos(config: Config, recipients: list[str]) -> bool:
    if not config.inbox_address:
        return False
    return any(address.lower() == config.inbox_address.lower() for address in recipients)


def extract_trigger_command(config: Config, subject: str, body: str) -> str | None:
    prefix = config.email_trigger_prefix
    subject_clean = subject.strip()
    if subject_clean.lower().startswith(prefix):
        command = subject_clean[len(prefix):].strip()
        return command or "Fais un audit complet du systeme."

    for line in body.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(prefix):
            command = stripped[len(prefix):].strip()
            return command or "Fais un audit complet du systeme."
    return None


def merge_analysis(heuristic: dict[str, Any], codex_result: dict[str, Any] | None) -> dict[str, Any]:
    if not codex_result:
        return {
            "severity": heuristic["severity"],
            "urgent": heuristic["urgent"],
            "send_email": heuristic["send_email"],
            "summary": heuristic["summary"],
            "findings": heuristic["findings"],
            "recommended_actions": heuristic["recommended_actions"],
            "needs_user_reply": False,
            "reply_subject": "[DefendOS] Rapport de surveillance",
            "reply_body": render_fallback_reply_body(heuristic),
        }

    merged = dict(codex_result)
    merged["severity"] = max_severity(heuristic["severity"], codex_result.get("severity", "info"))
    merged["urgent"] = bool(codex_result.get("urgent")) or bool(heuristic["urgent"])
    merged["send_email"] = bool(codex_result.get("send_email")) or bool(heuristic["send_email"])

    for finding in heuristic["findings"]:
        if finding not in merged["findings"]:
            merged["findings"].append(finding)

    for action in heuristic["recommended_actions"]:
        if action not in merged["recommended_actions"]:
            merged["recommended_actions"].append(action)

    codex_summary = str(codex_result.get("summary") or "").lower()
    if codex_summary.startswith("codex a expire"):
        merged["summary"] = heuristic["summary"]
        merged["reply_subject"] = "[DefendOS] Rapport de surveillance"
        merged["reply_body"] = render_fallback_reply_body(merged)

    return merged


def render_fallback_reply_body(payload: dict[str, Any]) -> str:
    lines = [
        f"Severite: {payload['severity']}",
        "",
        payload["summary"],
        "",
        "Constats:",
    ]
    lines.extend(f"- {finding}" for finding in payload["findings"])
    if payload["recommended_actions"]:
        lines.append("")
        lines.append("Actions recommandees:")
        lines.extend(f"- {action}" for action in payload["recommended_actions"])
    return "\n".join(lines)


def run_investigation(
    config: Config,
    *,
    trigger_kind: str,
    operator_request: str | None,
    skip_codex: bool,
) -> dict[str, Any]:
    run_dir = create_run_dir(config, trigger_kind)
    healthcheck = run_healthcheck(config, run_dir)
    heuristic = heuristic_analysis(healthcheck["report"], config)

    context = {
        "generated_at": utc_now_text(),
        "trigger_kind": trigger_kind,
        "operator_request": operator_request,
        "heuristic": heuristic,
        "healthcheck_exit_code": healthcheck["exit_code"],
        "expected_public_ports": config.expected_public_ports,
        "trusted_login_ips": config.trusted_login_ips,
    }
    write_json(run_dir / "context.json", context)

    codex_result: dict[str, Any] | None = None
    if config.codex_enabled and not skip_codex:
        prompt = build_codex_prompt(
            config,
            trigger_kind=trigger_kind,
            operator_request=operator_request,
            heuristic=heuristic,
        )
        write_text(run_dir / "codex-prompt.txt", prompt + "\n")
        codex_result = run_codex_investigation(
            config,
            run_dir=run_dir,
            prompt=prompt,
            timeout_seconds=codex_timeout_for_trigger(config, trigger_kind),
        )
        if codex_result is not None:
            write_json(run_dir / "codex-result.json", codex_result)

    final_result = merge_analysis(heuristic, codex_result)
    summary = {
        "run_id": run_dir.name,
        "run_dir": str(run_dir),
        "trigger_kind": trigger_kind,
        "generated_at": utc_now().isoformat(),
        "healthcheck_exit_code": healthcheck["exit_code"],
        "final_result": final_result,
        "heuristic": heuristic,
        "codex_result_present": codex_result is not None,
    }
    write_json(run_dir / "summary.json", summary)
    append_event(
        config,
        "run_completed",
        {
            "run_id": run_dir.name,
            "trigger_kind": trigger_kind,
            "severity": final_result["severity"],
            "summary": final_result["summary"],
        },
    )
    return summary


def normalize_resend_received_email(record: dict[str, Any]) -> InboundMessage:
    headers = record.get("headers") if isinstance(record.get("headers"), dict) else {}
    sender_display, sender_email = parseaddr(record.get("from") or "")
    recipients = [address.strip().lower() for address in (record.get("to") or []) if isinstance(address, str)]
    message_id = record.get("message_id") or header_lookup(headers, "Message-ID") or f"<resend-{record.get('id')}@defendos>"
    body = (record.get("text") or "").strip()
    if not body:
        body = strip_html(record.get("html") or "")
    return InboundMessage(
        provider="resend",
        unique_id=f"resend:{record.get('id')}",
        source_id=str(record.get("id") or ""),
        message_id=message_id,
        subject=str(record.get("subject") or ""),
        sender_email=sender_email.strip().lower(),
        sender_display=sender_display,
        recipients=recipients,
        references=header_lookup(headers, "References"),
        in_reply_to=header_lookup(headers, "In-Reply-To"),
        body=body,
        created_at=record.get("created_at"),
        raw=record,
    )


def normalize_imap_message(raw_message: bytes) -> InboundMessage:
    parsed = BytesParser(policy=default).parsebytes(raw_message)
    subject = decode_mime_header(parsed.get("Subject"))
    sender_display, sender_email = parseaddr(parsed.get("From") or "")
    recipients = [address.strip().lower() for _, address in getaddresses(parsed.get_all("to", []) + parsed.get_all("cc", []))]
    message_id = parsed.get("Message-ID", "").strip() or f"<imap-{hash(raw_message)}@defendos>"
    return InboundMessage(
        provider="imap",
        unique_id=f"imap:{message_id}",
        source_id=message_id,
        message_id=message_id,
        subject=subject,
        sender_email=sender_email.strip().lower(),
        sender_display=sender_display,
        recipients=recipients,
        references=parsed.get("References"),
        in_reply_to=parsed.get("In-Reply-To"),
        body=extract_message_text(parsed),
        created_at=parsed.get("Date"),
        raw={"message_id": message_id},
    )


def process_inbound_message(
    config: Config,
    *,
    inbound: InboundMessage,
    processed_message_ids: set[str],
    remember_ignored: bool,
    skip_codex: bool,
) -> bool:
    if not inbound.sender_email or inbound.unique_id in processed_message_ids:
        return False

    if not email_is_addressed_to_defendos(config, inbound.recipients):
        if remember_ignored:
            processed_message_ids.add(inbound.unique_id)
            save_processed_message_ids(config, processed_message_ids)
        return False

    if not sender_is_allowed(config, inbound.sender_email):
        append_event(
            config,
            "email_ignored",
            {
                "provider": inbound.provider,
                "message_id": inbound.message_id,
                "sender": inbound.sender_email,
                "reason": "sender_not_allowed",
            },
        )
        if remember_ignored:
            processed_message_ids.add(inbound.unique_id)
            save_processed_message_ids(config, processed_message_ids)
        return False

    trigger_command = extract_trigger_command(config, inbound.subject, inbound.body)
    if not trigger_command:
        if remember_ignored:
            processed_message_ids.add(inbound.unique_id)
            save_processed_message_ids(config, processed_message_ids)
        return False

    append_event(
        config,
        "email_received",
        {
            "provider": inbound.provider,
            "message_id": inbound.message_id,
            "sender": inbound.sender_email,
            "subject": inbound.subject,
        },
    )

    summary = run_investigation(
        config,
        trigger_kind="email-command",
        operator_request=trigger_command,
        skip_codex=skip_codex,
    )
    final_result = summary["final_result"]
    reply_subject = final_result["reply_subject"]
    if not reply_subject.lower().startswith("re:"):
        reply_subject = f"Re: {inbound.subject or reply_subject}"

    reply_body = final_result["reply_body"]
    write_text(Path(summary["run_dir"]) / "email-request.txt", inbound.body + "\n")

    reply_references = " ".join(part for part in [inbound.references, inbound.message_id] if part).strip() or None
    send_email(
        config,
        to_address=inbound.sender_email,
        subject=reply_subject,
        body=reply_body,
        in_reply_to=inbound.message_id or None,
        references=reply_references,
    )

    processed_message_ids.add(inbound.unique_id)
    save_processed_message_ids(config, processed_message_ids)
    append_event(
        config,
        "email_replied",
        {
            "provider": inbound.provider,
            "message_id": inbound.message_id,
            "sender": inbound.sender_email,
            "run_id": summary["run_id"],
        },
    )
    print(f"Processed email command from {inbound.sender_email}: {trigger_command}")
    return True


def poll_inbox_via_resend(config: Config, remember_ignored: bool, skip_codex: bool) -> dict[str, Any]:
    processed_message_ids = load_processed_message_ids(config)
    processed_count = 0
    ignored_count = 0

    payload = resend_request(
        config,
        "GET",
        "/emails/receiving",
        params={"limit": config.max_inbox_messages},
    )
    items = payload.get("data") if isinstance(payload.get("data"), list) else []
    items = sorted(items, key=lambda item: str(item.get("created_at") or ""))

    for item in items:
        source_id = str(item.get("id") or "")
        unique_id = f"resend:{source_id}"
        if not source_id or unique_id in processed_message_ids:
            continue

        detail = resend_request(config, "GET", f"/emails/receiving/{source_id}")
        inbound = normalize_resend_received_email(detail)
        handled = process_inbound_message(
            config,
            inbound=inbound,
            processed_message_ids=processed_message_ids,
            remember_ignored=remember_ignored,
            skip_codex=skip_codex,
        )
        if handled:
            processed_count += 1
        elif remember_ignored:
            ignored_count += 1

    result = {
        "provider": "resend",
        "processed_messages": processed_count,
        "ignored_messages": ignored_count,
        "checked_messages": len(items),
    }
    write_json(config.inbox_state_path, {"last_poll": utc_now().isoformat(), **result})
    append_event(config, "inbox_poll", result)
    return result


def poll_inbox_via_imap(config: Config, remember_ignored: bool, skip_codex: bool) -> dict[str, Any]:
    if not config.imap_host or not config.imap_username or not config.imap_password:
        raise RuntimeError("IMAP is not fully configured")

    processed_message_ids = load_processed_message_ids(config)
    processed_count = 0
    ignored_count = 0
    checked_messages = 0

    with imaplib.IMAP4_SSL(config.imap_host, config.imap_port) as mailbox:
        mailbox.login(config.imap_username, config.imap_password)
        mailbox.select(config.imap_folder)
        status, payload = mailbox.uid("search", None, "UNSEEN")
        if status != "OK":
            raise RuntimeError("Failed to search the IMAP inbox")

        message_uids = [item for item in payload[0].split() if item][-config.max_inbox_messages :]

        for uid in message_uids:
            fetch_status, fetch_payload = mailbox.uid("fetch", uid, "(RFC822)")
            if fetch_status != "OK":
                continue

            raw_message = b""
            for part in fetch_payload:
                if isinstance(part, tuple):
                    raw_message = part[1]
                    break
            if not raw_message:
                continue

            checked_messages += 1
            inbound = normalize_imap_message(raw_message)
            handled = process_inbound_message(
                config,
                inbound=inbound,
                processed_message_ids=processed_message_ids,
                remember_ignored=remember_ignored,
                skip_codex=skip_codex,
            )
            if handled:
                processed_count += 1
                mailbox.uid("store", uid, "+FLAGS", "(\\Seen)")
            elif remember_ignored:
                ignored_count += 1
                mailbox.uid("store", uid, "+FLAGS", "(\\Seen)")

    result = {
        "provider": "imap",
        "processed_messages": processed_count,
        "ignored_messages": ignored_count,
        "checked_messages": checked_messages,
    }
    write_json(config.inbox_state_path, {"last_poll": utc_now().isoformat(), **result})
    append_event(config, "inbox_poll", result)
    return result


def poll_inbox(config: Config, remember_ignored: bool, skip_codex: bool = False) -> dict[str, Any]:
    if config.inbox_provider == "imap" and not (config.imap_host and config.imap_username and config.imap_password):
        result = {
            "provider": "imap",
            "processed_messages": 0,
            "ignored_messages": 0,
            "checked_messages": 0,
            "skipped": True,
            "reason": "imap_not_fully_configured",
        }
        write_json(config.inbox_state_path, {"last_poll": utc_now().isoformat(), **result})
        append_event(config, "inbox_poll_skipped", result)
        return result

    if config.inbox_provider == "resend" and not config.resend_api_key:
        result = {
            "provider": "resend",
            "processed_messages": 0,
            "ignored_messages": 0,
            "checked_messages": 0,
            "skipped": True,
            "reason": "resend_not_configured",
        }
        write_json(config.inbox_state_path, {"last_poll": utc_now().isoformat(), **result})
        append_event(config, "inbox_poll_skipped", result)
        return result

    if config.inbox_provider == "resend":
        return poll_inbox_via_resend(config, remember_ignored, skip_codex)
    return poll_inbox_via_imap(config, remember_ignored, skip_codex)


def list_recent_runs(config: Config, limit: int = 20) -> list[dict[str, Any]]:
    run_dirs = sorted(
        [path for path in config.runs_dir.iterdir() if path.is_dir()],
        key=lambda path: path.name,
        reverse=True,
    )[:limit]

    results: list[dict[str, Any]] = []
    for run_dir in run_dirs:
        summary_path = run_dir / "summary.json"
        if not summary_path.exists():
            continue
        summary = read_json(summary_path, {})
        if isinstance(summary, dict):
            results.append(summary)
    return results


def read_run_detail(config: Config, run_id: str) -> dict[str, Any] | None:
    safe_run_id = Path(run_id).name
    run_dir = config.runs_dir / safe_run_id
    summary_path = run_dir / "summary.json"
    if not summary_path.exists():
        return None

    detail = read_json(summary_path, {})
    if not isinstance(detail, dict):
        return None

    for filename in ["healthcheck.txt", "codex-result.json", "codex-stdout.log", "codex-stderr.log", "context.json"]:
        path = run_dir / filename
        if not path.exists():
            continue
        if filename.endswith(".json"):
            detail[filename] = read_json(path, {})
        else:
            detail[filename] = path.read_text(encoding="utf-8", errors="replace")[-12000:]
    return detail


def build_status_payload(config: Config) -> dict[str, Any]:
    recent_runs = list_recent_runs(config, limit=12)
    latest_run = recent_runs[0] if recent_runs else None
    codex_ready = bool(resolve_codex_bin(config) and config.openai_api_key)
    resend_ready = bool(config.resend_api_key)
    smtp_ready = bool(config.smtp_host and config.smtp_username and config.smtp_password)
    imap_ready = bool(config.imap_host and config.imap_username and config.imap_password)
    config_payload = {
        "email_provider": config.email_provider,
        "inbox_provider": config.inbox_provider,
        "alert_email_to": config.alert_email_to,
        "inbox_address": config.inbox_address,
        "allowed_senders": config.allowed_senders,
        "expected_public_ports": config.expected_public_ports,
        "trusted_login_ips": config.trusted_login_ips,
        "codex_bin": resolve_codex_bin(config) or config.codex_bin,
        "codex_model": config.codex_model,
        "codex_timeout_seconds": config.codex_timeout_seconds,
        "codex_scheduled_timeout_seconds": config.codex_scheduled_timeout_seconds,
        "codex_ready": codex_ready,
        "resend_ready": resend_ready,
        "smtp_ready": smtp_ready,
        "imap_ready": imap_ready,
        "dashboard_bind": f"{config.dashboard_host}:{config.dashboard_port}",
        "external_env_files": [str(path) for path in config.external_env_files],
    }
    return {
        "generated_at": utc_now().isoformat(),
        "latest_run": latest_run,
        "recent_runs": recent_runs,
        "events": list(reversed(read_jsonl_tail(config.events_log_path, 30))),
        "last_alert": read_json(config.last_alert_path, {}),
        "inbox_state": read_json(config.inbox_state_path, {}),
        "config": config_payload,
    }


def spawn_background_job(config: Config, command_args: list[str]) -> dict[str, Any]:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    log_path = config.jobs_dir / f"{timestamp}-{slugify('-'.join(command_args))}.log"
    config.jobs_dir.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as handle:
        process = subprocess.Popen(
            [sys.executable, str(config.base_dir / "defendos.py"), *command_args],
            cwd=str(config.base_dir),
            env=build_subprocess_env(config),
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    append_event(
        config,
        "job_started",
        {
            "pid": process.pid,
            "command": command_args,
            "log_path": str(log_path),
        },
    )
    return {
        "ok": True,
        "pid": process.pid,
        "command": command_args,
        "log_path": str(log_path),
    }


class DefendOSHandler(BaseHTTPRequestHandler):
    server_version = "DefendOS/1.0"

    @property
    def defend_config(self) -> Config:
        return self.server.defend_config  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        append_event(
            self.defend_config,
            "dashboard_http",
            {"message": fmt % args},
        )

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        encoded = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def serve_dashboard(self) -> None:
        html_path = self.defend_config.dashboard_html_path
        if html_path.exists():
            content = html_path.read_text(encoding="utf-8")
        else:
            content = DEFAULT_DASHBOARD_HTML
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self.serve_dashboard()
            return

        if parsed.path == "/api/status":
            self.send_json(build_status_payload(self.defend_config))
            return

        if parsed.path == "/api/run":
            params = parse_qs(parsed.query)
            run_id = (params.get("id") or [""])[0]
            detail = read_run_detail(self.defend_config, run_id)
            if detail is None:
                self.send_json({"error": "Run not found"}, status=404)
                return
            self.send_json(detail)
            return

        self.send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        body = self.read_json_body()

        if parsed.path == "/api/actions/healthcheck":
            self.send_json(spawn_background_job(self.defend_config, ["healthcheck"]))
            return

        if parsed.path == "/api/actions/poll-inbox":
            self.send_json(spawn_background_job(self.defend_config, ["poll-inbox"]))
            return

        if parsed.path == "/api/actions/investigate":
            request_text = str(body.get("request") or "").strip()
            args = ["investigate"]
            if request_text:
                args.extend(["--request", request_text])
            self.send_json(spawn_background_job(self.defend_config, args))
            return

        if parsed.path == "/api/actions/self-test":
            self.send_json(spawn_background_job(self.defend_config, ["self-test"]))
            return

        self.send_json({"error": "Not found"}, status=404)


def healthcheck_command(config: Config, args: argparse.Namespace) -> int:
    with FileLock(config.locks_dir / "healthcheck.lock"):
        summary = run_investigation(
            config,
            trigger_kind="scheduled-healthcheck",
            operator_request=args.note,
            skip_codex=args.skip_codex,
        )

        final_result = summary["final_result"]
        print(json.dumps(summary, indent=2, ensure_ascii=True))

        if args.no_email or not config.alert_email_to:
            return 0 if severity_rank(final_result["severity"]) < severity_rank("high") else 2

        fingerprint = "|".join(
            [
                final_result["severity"],
                final_result["summary"],
                ";".join(final_result["findings"]),
            ]
        )

        if should_suppress_alert(config, fingerprint):
            print("DefendOS: duplicate alert suppressed.")
            return 0 if severity_rank(final_result["severity"]) < severity_rank("high") else 2

        if not final_result["send_email"]:
            return 0 if severity_rank(final_result["severity"]) < severity_rank("high") else 2

        send_email(
            config,
            to_address=config.alert_email_to,
            subject=final_result["reply_subject"],
            body=final_result["reply_body"],
        )
        remember_alert(config, fingerprint)
        return 0 if severity_rank(final_result["severity"]) < severity_rank("high") else 2


def investigate_command(config: Config, args: argparse.Namespace) -> int:
    with FileLock(config.locks_dir / "investigate.lock"):
        summary = run_investigation(
            config,
            trigger_kind="manual-investigation",
            operator_request=args.request,
            skip_codex=args.skip_codex,
        )
        print(json.dumps(summary, indent=2, ensure_ascii=True))
        if args.email and config.alert_email_to:
            final_result = summary["final_result"]
            send_email(
                config,
                to_address=config.alert_email_to,
                subject=final_result["reply_subject"],
                body=final_result["reply_body"],
            )
        return 0


def poll_inbox_command(config: Config, args: argparse.Namespace) -> int:
    with FileLock(config.locks_dir / "mailbox.lock"):
        result = poll_inbox(config, args.mark_seen_ignored, args.skip_codex)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0


def self_test_command(config: Config, args: argparse.Namespace) -> int:
    with FileLock(config.locks_dir / "self-test.lock"):
        token = utc_now().strftime("%Y%m%dT%H%M%SZ")
        results: dict[str, Any] = {
            "token": token,
            "generated_at": utc_now().isoformat(),
            "tests": {},
        }

        if config.alert_email_to:
            subject = f"[DefendOS] Test sortant {token}"
            body = f"Test DefendOS sortant.\n\nToken: {token}\nHeure: {utc_now_text()}"
            results["tests"]["outbound_email"] = send_email(
                config,
                to_address=config.alert_email_to,
                subject=subject,
                body=body,
            )

        if args.skip_codex:
            results["tests"]["codex_smoke"] = {
                "ok": False,
                "skipped": True,
            }
        else:
            results["tests"]["codex_smoke"] = run_codex_smoke_test(config)

        investigation = run_investigation(
            config,
            trigger_kind="self-test",
            operator_request=f"Mode test DefendOS. Verifie les signaux principaux. Token: {token}",
            skip_codex=True,
        )
        results["tests"]["heuristic_investigation"] = {
            "run_id": investigation["run_id"],
            "severity": investigation["final_result"]["severity"],
            "summary": investigation["final_result"]["summary"],
        }

        if config.inbox_provider == "resend" and config.inbox_address and config.resend_test_from_email:
            test_sender = parse_address(config.resend_test_from_email)
            if test_sender and sender_is_allowed(config, test_sender):
                command_subject = f"{config.email_trigger_prefix} test e2e {token}"
                command_body = f"{config.email_trigger_prefix} fais un court diagnostic et mentionne le token {token}"
                results["tests"]["inbound_command_seed"] = send_email(
                    config,
                    to_address=config.inbox_address,
                    subject=command_subject,
                    body=command_body,
                    from_override=config.resend_test_from_email,
                )
                processed = False
                for _ in range(max(1, args.wait_seconds // 10)):
                    time.sleep(10)
                    poll_result = poll_inbox(config, remember_ignored=True, skip_codex=True)
                    if poll_result["processed_messages"] > 0:
                        processed = True
                        results["tests"]["inbound_poll"] = poll_result
                        break
                results["tests"]["reply_chain"] = {
                    "attempted": True,
                    "processed": processed,
                }
            else:
                results["tests"]["reply_chain"] = {
                    "attempted": False,
                    "reason": "resend_test_from_email_not_allowed",
                }
        else:
            results["tests"]["reply_chain"] = {
                "attempted": False,
                "reason": "inbox_provider_not_ready",
            }

        append_event(config, "self_test", results)
        print(json.dumps(results, indent=2, ensure_ascii=True))
        return 0


def serve_dashboard_command(config: Config, args: argparse.Namespace) -> int:
    host = args.host or config.dashboard_host
    port = args.port or config.dashboard_port

    if not config.dashboard_html_path.exists():
        write_text(config.dashboard_html_path, DEFAULT_DASHBOARD_HTML)

    server = ThreadingHTTPServer((host, port), DefendOSHandler)
    server.defend_config = config  # type: ignore[attr-defined]
    append_event(config, "dashboard_started", {"host": host, "port": port})
    print(f"DefendOS dashboard listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        append_event(config, "dashboard_stopped", {"host": host, "port": port})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DefendOS global VPS surveillance agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    healthcheck_parser = subparsers.add_parser("healthcheck", help="Run a scheduled healthcheck")
    healthcheck_parser.add_argument("--skip-codex", action="store_true", help="Skip Codex investigation")
    healthcheck_parser.add_argument("--no-email", action="store_true", help="Do not send an email")
    healthcheck_parser.add_argument("--note", default=None, help="Optional operator note to include in the run")

    inbox_parser = subparsers.add_parser("poll-inbox", help="Poll the inbox once")
    inbox_parser.add_argument(
        "--mark-seen-ignored",
        action="store_true",
        help="Remember ignored messages to avoid reprocessing them",
    )
    inbox_parser.add_argument("--skip-codex", action="store_true", help="Skip Codex during email-triggered runs")

    investigate_parser = subparsers.add_parser("investigate", help="Run a manual investigation")
    investigate_parser.add_argument("--request", default=None, help="Operator request for Codex")
    investigate_parser.add_argument("--skip-codex", action="store_true", help="Skip Codex")
    investigate_parser.add_argument("--email", action="store_true", help="Send the result by email")

    self_test_parser = subparsers.add_parser("self-test", help="Run outbound and inbound self tests")
    self_test_parser.add_argument("--skip-codex", action="store_true", help="Skip Codex during self test")
    self_test_parser.add_argument("--wait-seconds", type=int, default=60, help="Max wait time for inbound email processing")

    serve_parser = subparsers.add_parser("serve", help="Serve the local dashboard")
    serve_parser.add_argument("--host", default=None, help="Bind host")
    serve_parser.add_argument("--port", type=int, default=None, help="Bind port")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = build_config()

    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.runs_dir.mkdir(parents=True, exist_ok=True)
    config.locks_dir.mkdir(parents=True, exist_ok=True)
    config.jobs_dir.mkdir(parents=True, exist_ok=True)

    if args.command == "healthcheck":
        return healthcheck_command(config, args)
    if args.command == "poll-inbox":
        return poll_inbox_command(config, args)
    if args.command == "investigate":
        return investigate_command(config, args)
    if args.command == "self-test":
        return self_test_command(config, args)
    if args.command == "serve":
        return serve_dashboard_command(config, args)

    parser.error("Unknown command")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"DefendOS error: {error}", file=sys.stderr)
        raise SystemExit(1)
