import os
import json
import re
import time
import math
import hashlib
import sqlite3
import threading
import uuid
import subprocess
import shutil
import hmac
import secrets
from pathlib import Path
from datetime import date, datetime, timezone
from functools import wraps
from typing import Literal, Optional

import jwt
import requests
from flask import (
    Flask, jsonify, request, send_file, session, redirect, url_for,
    render_template, abort,
)
from jwt import PyJWKClient
from openai import OpenAI
from pydantic import BaseModel, Field
from werkzeug.exceptions import HTTPException
import imageio_ffmpeg


# ============================================================
# APP
# ============================================================

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024


# ============================================================
# ENVIRONMENT CONFIG
# ============================================================

# Microsoft Entra
ENTRA_TENANT_ID = os.environ["ENTRA_TENANT_ID"]
ENTRA_API_CLIENT_ID = os.environ["ENTRA_API_CLIENT_ID"]

# Salesforce
SF_CLIENT_ID = os.environ["SF_CLIENT_ID"]
SF_LOGIN_URL = os.environ["SF_LOGIN_URL"].rstrip("/")
SF_JWT_PRIVATE_KEY = os.environ["SF_JWT_PRIVATE_KEY"].replace("\\n", "\n")
SF_JWT_AUDIENCE = "https://login.salesforce.com"
SF_API_VERSION = os.environ.get("SF_API_VERSION", "67.0")

# OpenAI
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]

# Used only to sign short-lived write-confirmation tokens.
# Generate a long random value and keep it only in Render.
APP_SIGNING_SECRET = os.environ["APP_SIGNING_SECRET"]

# CMD Sally V3 pilot: location + Sessions.
DEMO_GEO_ENABLED = os.environ.get("DEMO_GEO_ENABLED", "true").strip().lower() not in {"0", "false", "no"}
DEMO_GEO_REAL_RADIUS_KM = float(os.environ.get("DEMO_GEO_REAL_RADIUS_KM", "250"))
SESSION_STORAGE_ROOT = Path(os.environ.get("SESSION_STORAGE_ROOT", "/var/data/cmd-sally"))
SESSION_AUTO_LINK_THRESHOLD = float(os.environ.get("SESSION_AUTO_LINK_THRESHOLD", "0.82"))
MAX_OPENAI_AUDIO_BYTES = 24_000_000  # leave headroom below the 25 MB API ceiling
SESSION_CHUNK_SECONDS = int(os.environ.get("SESSION_CHUNK_SECONDS", "1200"))

# Demo admin console. No default password is provided: /admin remains unavailable
# until these values are configured in Render.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ADMIN_SESSION_SECRET = os.environ.get("ADMIN_SESSION_SECRET", "").strip()
ADMIN_COOKIE_SECURE = os.environ.get("ADMIN_COOKIE_SECURE", "true").strip().lower() not in {"0", "false", "no"}
CHAT_JOB_MAX_CONCURRENT = max(1, int(os.environ.get("CHAT_JOB_MAX_CONCURRENT", "2")))
CHAT_JOB_TTL_SECONDS = max(300, int(os.environ.get("CHAT_JOB_TTL_SECONDS", "3600")))

app.secret_key = ADMIN_SESSION_SECRET or APP_SIGNING_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=ADMIN_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
)

openai_client = OpenAI(api_key=OPENAI_API_KEY)


# ============================================================
# SESSION STORAGE + SQLITE (PILOT)
# ============================================================


def _ensure_session_storage():
    global SESSION_STORAGE_ROOT
    try:
        SESSION_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
        probe = SESSION_STORAGE_ROOT / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except Exception:
        # Local/dev safety fallback. On Render, attach a Persistent Disk at
        # /var/data and keep SESSION_STORAGE_ROOT=/var/data/cmd-sally.
        SESSION_STORAGE_ROOT = Path("/tmp/cmd-sally")
        SESSION_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)


_ensure_session_storage()
SESSION_DB_PATH = SESSION_STORAGE_ROOT / "sessions.db"
SESSION_AUDIO_ROOT = SESSION_STORAGE_ROOT / "sessions"
SESSION_DELETED_ROOT = SESSION_STORAGE_ROOT / "deleted_sessions"
SESSION_AUDIO_ROOT.mkdir(parents=True, exist_ok=True)
SESSION_DELETED_ROOT.mkdir(parents=True, exist_ok=True)


def session_db():
    conn = sqlite3.connect(str(SESSION_DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(conn, table_name, column_name, ddl):
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if column_name not in columns:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}")


def init_session_db():
    with session_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                owner_oid TEXT NOT NULL,
                salesforce_username TEXT NOT NULL,
                title TEXT,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                started_at TEXT,
                ended_at TEXT,
                duration_ms INTEGER,
                audio_path TEXT,
                audio_bytes INTEGER,
                transcript_json_path TEXT,
                transcript_text_path TEXT,
                summary_json_path TEXT,
                linked_opportunity_id TEXT,
                linked_opportunity_name TEXT,
                link_confidence REAL,
                suggested_opportunity_id TEXT,
                suggested_opportunity_name TEXT,
                suggested_confidence REAL,
                link_reason TEXT,
                actual_location_json TEXT,
                effective_location_json TEXT,
                voicepuck_json TEXT,
                processing_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(conn, "sessions", "deleted_at", "TEXT")
        _ensure_column(conn, "sessions", "deleted_by", "TEXT")
        _ensure_column(conn, "sessions", "deleted_archive_path", "TEXT")

        conn.execute(
            """CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                owner_oid TEXT,
                salesforce_username TEXT,
                request_id TEXT,
                summary TEXT,
                details_json TEXT
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS config_feature_flags (
                key TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS config_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT,
                updated_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS config_workflows (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                triggers_json TEXT NOT NULL,
                steps_json TEXT NOT NULL,
                tools_json TEXT NOT NULL,
                confirmation_required INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS config_jargon (
                id TEXT PRIMARY KEY,
                term TEXT NOT NULL,
                aliases_json TEXT NOT NULL,
                pronunciation TEXT,
                category TEXT,
                definition TEXT NOT NULL,
                examples TEXT,
                stt_priority TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS config_knowledge (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT,
                content TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        conn.commit()


def seed_demo_admin_config():
    now = datetime.now(timezone.utc).isoformat()
    default_flags = {
        "salesforce_reads": True,
        "salesforce_writes": True,
        "web_research": True,
        "session_recording": True,
        "session_soft_delete": True,
        "location": True,
        "demo_geography": DEMO_GEO_ENABLED,
        "long_research": True,
        "voice_chat": True,
    }
    default_workflows = [
        ("nearby_visit", "Nearby Visit", "Recover field time by finding useful nearby customer stops.", ["who can I visit near me", "nearby customers", "meeting cancelled"], ["Resolve effective location", "Query open-opportunity accounts", "Rank by distance and pipeline", "Return contact and opportunity context"], ["location", "Salesforce"], 0, 1),
        ("pre_meeting", "Pre-Meeting Brief", "Build a concise briefing before an upcoming customer meeting.", ["prepare me for", "brief me before", "meeting prep"], ["Resolve Event", "Load Account and Opportunity", "Load primary contacts", "Review Events and Tasks", "Optional public web research", "Generate briefing"], ["Salesforce", "web_search"], 0, 1),
        ("opp_risk", "Opportunity Risk Review", "Review deal signals, forecast consistency, activity and next steps.", ["deal risk", "what should I worry about", "forecast risk"], ["Query relevant Opportunities", "Review forecast/confidence", "Review activity", "Highlight inconsistencies", "Recommend next actions"], ["Salesforce"], 0, 1),
        ("competitive_scan", "Competitive Scan", "Combine CRM context with current public competitor research.", ["competitor", "competitive research", "how do we win"], ["Load Opportunity context", "Search public sources", "Compare competitor position", "Build win strategy"], ["Salesforce", "web_search"], 0, 1),
        ("follow_up", "Follow-Up Assistant", "Turn meeting context into a clean follow-up plan.", ["follow up", "what should I send", "after the meeting"], ["Load latest Session/Event", "Extract commitments", "Draft follow-up", "Propose CRM action if requested"], ["Salesforce", "Sessions"], 1, 1),
        ("quarter_rescue", "Quarter Rescue", "Surface risky high-value deals that can still be influenced this quarter.", ["quarter rescue", "save the quarter", "what can still close"], ["Query open quarter pipeline", "Rank by value and risk", "Review activity and confidence", "Recommend priorities"], ["Salesforce"], 0, 0),
    ]
    default_jargon = [
        ("cmd", "CMD", ["chromatography and mass spectrometry division"], "C M D", "Organization", "Chromatography and Mass Spectrometry Division"),
        ("tss", "TSS", ["technical sales specialist"], "T S S", "Role", "Technical Sales Specialist"),
        ("am", "AM", ["account manager"], "A M", "Role", "Account Manager"),
        ("dm", "DM", ["district manager"], "D M", "Role", "District Manager"),
        ("pn", "PN", ["project number", "sfdc project number"], "P N", "Salesforce", "SFDC Project Number generated on the Opportunity"),
        ("astral", "Astral", ["orbitrap astral"], "ass-truhl", "Product", "Orbitrap Astral mass spectrometer family"),
        ("excedion", "Excedion", ["exceedion", "excedian", "exceed ian"], "ex-see-dee-on", "Product", "Orbitrap Excedion mass spectrometer family"),
        ("vanquish", "Vanquish", ["vanquish neo"], "van-kwish", "Product", "Vanquish liquid chromatography platform"),
        ("faims", "FAIMS", ["faims pro", "fames"], "fames", "Product", "High-field asymmetric waveform ion mobility separation"),
        ("hram", "HRAM", ["high resolution accurate mass"], "H ram", "Technical", "High-resolution accurate-mass mass spectrometry"),
    ]
    default_knowledge = [
        ("forecast_commit", "Commit", "Forecast", "Demo interpretation: a deal the rep expects to close in the forecast period; treat Stage, Confidence Level and Add to Forecast as separate signals rather than synonyms."),
        ("forecast_best_case", "Best Case", "Forecast", "Demo interpretation: a strong opportunity that may close in the forecast period but is not yet a Commit."),
        ("stale_rule", "Stale Opportunity", "Business Rule", "For demo analysis, a useful risk signal is an open Opportunity whose close date is approaching while meaningful customer activity or next-step evidence is old or missing. Do not silently impose a fixed threshold unless the user asks or a workflow defines one."),
        ("truth_boundary", "Demo Data Boundary", "Safety", "Organizations and public professional identities in the pilot dataset may be real/public. Opportunity values, buying intent, activities, comments and commercial history are synthetic demo data and must never be presented as real confidential intelligence outside Salesforce demo context."),
    ]
    with session_db() as conn:
        for key, enabled in default_flags.items():
            conn.execute("INSERT OR IGNORE INTO config_feature_flags(key, enabled, updated_at) VALUES(?,?,?)", (key, int(enabled), now))
        for wid, name, desc, triggers, steps, tools, confirm, enabled in default_workflows:
            conn.execute("""INSERT OR IGNORE INTO config_workflows
                (id,name,description,triggers_json,steps_json,tools_json,confirmation_required,enabled,version,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,1,?,?)""", (wid,name,desc,json.dumps(triggers),json.dumps(steps),json.dumps(tools),confirm,enabled,now,now))
        for jid, term, aliases, pronunciation, category, definition in default_jargon:
            conn.execute("""INSERT OR IGNORE INTO config_jargon
                (id,term,aliases_json,pronunciation,category,definition,examples,stt_priority,enabled,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,1,?,?)""", (jid,term,json.dumps(aliases),pronunciation,category,definition,"","normal",now,now))
        for kid,title,category,content in default_knowledge:
            conn.execute("""INSERT OR IGNORE INTO config_knowledge
                (id,title,category,content,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?)""", (kid,title,category,content,now,now))
        conn.commit()


init_session_db()
seed_demo_admin_config()


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def audit_log(event_type, owner_oid=None, salesforce_username=None, request_id=None, summary=None, details=None):
    try:
        with session_db() as conn:
            conn.execute(
                """INSERT INTO audit_events
                (created_at,event_type,owner_oid,salesforce_username,request_id,summary,details_json)
                VALUES(?,?,?,?,?,?,?)""",
                (utc_now_iso(), str(event_type), owner_oid, salesforce_username, request_id,
                 (str(summary)[:500] if summary else None),
                 json.dumps(details or {}, default=str)[:12000]),
            )
            conn.commit()
    except Exception:
        pass


def get_feature_flags():
    with session_db() as conn:
        rows = conn.execute("SELECT key, enabled FROM config_feature_flags ORDER BY key").fetchall()
    return {row["key"]: bool(row["enabled"]) for row in rows}


def get_config_setting(key, default=None):
    with session_db() as conn:
        row = conn.execute("SELECT value_json FROM config_settings WHERE key=?", (str(key),)).fetchone()
    if not row or row["value_json"] is None:
        return default
    try:
        return json.loads(row["value_json"])
    except Exception:
        return default


def set_config_setting(key, value):
    with session_db() as conn:
        conn.execute(
            "INSERT INTO config_settings(key,value_json,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
            (str(key), json.dumps(value), utc_now_iso()),
        )
        conn.commit()


def feature_enabled(key, default=True):
    flags = get_feature_flags()
    return flags.get(key, default)


def get_active_workflows():
    with session_db() as conn:
        rows = conn.execute("SELECT * FROM config_workflows WHERE enabled=1 ORDER BY name").fetchall()
    out = []
    for row in rows:
        d = dict(row)
        d["triggers"] = json.loads(d.pop("triggers_json") or "[]")
        d["steps"] = json.loads(d.pop("steps_json") or "[]")
        d["tools"] = json.loads(d.pop("tools_json") or "[]")
        d["enabled"] = bool(d["enabled"])
        d["confirmation_required"] = bool(d["confirmation_required"])
        out.append(d)
    return out


def get_active_jargon():
    with session_db() as conn:
        rows = conn.execute("SELECT * FROM config_jargon WHERE enabled=1 ORDER BY term").fetchall()
    out = []
    for row in rows:
        d = dict(row)
        d["aliases"] = json.loads(d.pop("aliases_json") or "[]")
        d["enabled"] = bool(d["enabled"])
        out.append(d)
    return out


def get_active_knowledge():
    with session_db() as conn:
        rows = conn.execute("SELECT * FROM config_knowledge WHERE enabled=1 ORDER BY category,title").fetchall()
    return [dict(row) for row in rows]


def configurable_context_prompt():
    workflows = get_active_workflows()[:30]
    jargon = get_active_jargon()[:200]
    knowledge = get_active_knowledge()[:100]
    payload = {
        "configured_workflows": [
            {"id": w["id"], "name": w["name"], "description": w["description"],
             "triggers": w["triggers"], "steps": w["steps"], "tools": w["tools"],
             "confirmation_required": w["confirmation_required"]}
            for w in workflows
        ],
        "client_jargon": [
            {"term": j["term"], "aliases": j["aliases"], "definition": j["definition"],
             "category": j.get("category"), "pronunciation": j.get("pronunciation")}
            for j in jargon
        ],
        "client_knowledge": [
            {"title": k["title"], "category": k.get("category"), "content": k["content"]}
            for k in knowledge
        ],
    }
    return (
        "Client-configured demo context follows. Treat it as organization-specific guidance, "
        "not as proof of live Salesforce facts. Use a configured workflow when the user's intent "
        "clearly matches it. Jargon aliases may be used to normalize likely speech/transcription variants.\n"
        + json.dumps(payload, default=str)[:30000]
    )


def client_speech_context():
    """Return a compact list of active client terms/aliases for on-device STT hints."""
    values = []
    seen = set()
    for entry in get_active_jargon():
        candidates = [entry.get("term"), *(entry.get("aliases") or [])]
        for candidate in candidates:
            value = str(candidate or "").strip()
            key = value.lower()
            if value and key not in seen:
                seen.add(key)
                values.append(value)
            if len(values) >= 250:
                return values
    return values


def apply_jargon_normalization(text):
    value = str(text or "")
    if not value:
        return value
    replacements = []
    for entry in get_active_jargon():
        term = str(entry.get("term") or "").strip()
        if not term:
            continue
        for alias in entry.get("aliases") or []:
            alias = str(alias or "").strip()
            if len(alias) >= 3 and alias.lower() != term.lower():
                replacements.append((alias, term))
    replacements.sort(key=lambda pair: len(pair[0]), reverse=True)
    for alias, term in replacements:
        value = re.sub(r"(?i)(?<![A-Za-z0-9])" + re.escape(alias) + r"(?![A-Za-z0-9])", term, value)
    return value


def safe_session_id(value):
    raw = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,96}", raw):
        raise ValueError("Invalid session id.")
    return raw


def owner_session_row(session_id, owner_oid):
    with session_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ? AND owner_oid = ? AND deleted_at IS NULL",
            (safe_session_id(session_id), str(owner_oid)),
        ).fetchone()
    if not row:
        raise ValueError("Session not found for the authenticated user.")
    return row


def read_json_file(path_value, default=None):
    if not path_value:
        return default
    try:
        return json.loads(Path(path_value).read_text(encoding="utf-8"))
    except Exception:
        return default


def session_row_to_dict(row, include_summary=True):
    data = dict(row)
    summary = read_json_file(data.get("summary_json_path"), {}) if include_summary else None
    actual_location = json.loads(data.get("actual_location_json") or "null")
    effective_location = json.loads(data.get("effective_location_json") or "null")
    voicepuck = json.loads(data.get("voicepuck_json") or "null") or {
        "assigned": False,
        "connected": False,
        "device_id": None,
    }

    result = {
        "session_id": data.get("session_id"),
        "title": data.get("title") or "Untitled session",
        "status": data.get("status"),
        "source": data.get("source"),
        "started_at": data.get("started_at"),
        "ended_at": data.get("ended_at"),
        "duration_ms": data.get("duration_ms"),
        "audio_bytes": data.get("audio_bytes"),
        "has_audio": bool(data.get("audio_path")),
        "has_transcript": bool(data.get("transcript_json_path")),
        "actual_location": actual_location,
        "effective_location": effective_location,
        "voicepuck": voicepuck,
        "processing_error": data.get("processing_error"),
        "linked_opportunity": (
            {
                "id": data.get("linked_opportunity_id"),
                "name": data.get("linked_opportunity_name"),
                "confidence": data.get("link_confidence"),
            }
            if data.get("linked_opportunity_id") else None
        ),
        "suggested_opportunity": (
            {
                "id": data.get("suggested_opportunity_id"),
                "name": data.get("suggested_opportunity_name"),
                "confidence": data.get("suggested_confidence"),
                "reason": data.get("link_reason"),
            }
            if data.get("suggested_opportunity_id") else None
        ),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "deleted_at": data.get("deleted_at"),
        "deleted_by": data.get("deleted_by"),
    }
    if include_summary:
        result["summary"] = summary or None
    return result


# ============================================================
# MICROSOFT ENTRA TOKEN VERIFICATION
# ============================================================

ENTRA_ISSUER = (
    f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0"
)

ENTRA_JWKS_URL = (
    f"https://login.microsoftonline.com/"
    f"{ENTRA_TENANT_ID}/discovery/v2.0/keys"
)

entra_jwks_client = PyJWKClient(ENTRA_JWKS_URL)


def verify_entra_access_token(token):
    signing_key = entra_jwks_client.get_signing_key_from_jwt(token)

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=ENTRA_API_CLIENT_ID,
        issuer=ENTRA_ISSUER,
    )

    scopes = claims.get("scp", "").split()

    if "access_as_user" not in scopes:
        raise Exception("Required scope access_as_user is missing.")

    return claims


def require_auth(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing_bearer_token"}), 401

        token = auth_header.split(" ", 1)[1]

        try:
            claims = verify_entra_access_token(token)
        except Exception as e:
            return jsonify({
                "error": "invalid_token",
                "details": str(e),
            }), 401

        request.user_claims = claims
        return route_function(*args, **kwargs)

    return wrapper


# ============================================================
# SALESFORCE AUTH + REST
# ============================================================

def get_salesforce_access_token(salesforce_username):
    now = int(time.time())

    payload = {
        "iss": SF_CLIENT_ID,
        "sub": salesforce_username,
        "aud": SF_JWT_AUDIENCE,
        "exp": now + 180,
    }

    assertion = jwt.encode(
        payload,
        SF_JWT_PRIVATE_KEY,
        algorithm="RS256",
    )

    response = requests.post(
        f"{SF_LOGIN_URL}/services/oauth2/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        },
        timeout=30,
    )

    if not response.ok:
        raise Exception(
            "Salesforce authentication failed: "
            f"{response.status_code} {response.text}"
        )

    data = response.json()

    return {
        "access_token": data["access_token"],
        "instance_url": data["instance_url"],
    }


def salesforce_query(access_token, instance_url, soql):
    response = requests.get(
        f"{instance_url}/services/data/v{SF_API_VERSION}/query",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"q": soql},
        timeout=30,
    )

    if not response.ok:
        raise Exception(
            "Salesforce query failed: "
            f"{response.status_code} {response.text}"
        )

    return response.json()


def salesforce_update_opportunity(access_token, instance_url, opportunity_id, fields):
    response = requests.patch(
        f"{instance_url}/services/data/v{SF_API_VERSION}"
        f"/sobjects/Opportunity/{opportunity_id}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json=fields,
        timeout=30,
    )

    if response.status_code != 204:
        raise Exception(
            "Salesforce update failed: "
            f"{response.status_code} {response.text}"
        )

    return True


def salesforce_create_record(access_token, instance_url, object_name, fields):
    response = requests.post(
        f"{instance_url}/services/data/v{SF_API_VERSION}/sobjects/{object_name}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json=fields,
        timeout=30,
    )

    if response.status_code not in {200, 201}:
        raise Exception(
            f"Salesforce {object_name} create failed: "
            f"{response.status_code} {response.text}"
        )

    data = response.json()
    if not data.get("success") or not data.get("id"):
        raise Exception(
            f"Salesforce {object_name} create returned an unexpected response: {data}"
        )

    return data["id"]


def salesforce_update_record(access_token, instance_url, object_name, record_id, fields):
    response = requests.patch(
        f"{instance_url}/services/data/v{SF_API_VERSION}"
        f"/sobjects/{object_name}/{record_id}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json=fields,
        timeout=30,
    )

    if response.status_code != 204:
        raise Exception(
            f"Salesforce {object_name} update failed: "
            f"{response.status_code} {response.text}"
        )

    return True


# ============================================================
# SAFE SOQL / VALUE HELPERS
# ============================================================

def soql_escape(value):
    if value is None:
        return None

    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("'", "\\'")
    )


def soql_like_escape(value):
    if value is None:
        return None

    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def validate_iso_date(value):
    if value is None:
        return None

    date.fromisoformat(str(value))
    return str(value)


def parse_iso_datetime(value):
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        raise ValueError("Date/time cannot be empty.")

    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    parsed = datetime.fromisoformat(normalized)

    if parsed.tzinfo is None:
        raise ValueError(
            "Date/time must include a timezone offset, for example "
            "2026-08-18T14:00:00+05:30."
        )

    return parsed


def normalize_salesforce_datetime(value):
    parsed = parse_iso_datetime(value)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def salesforce_soql_datetime(value):
    parsed = parse_iso_datetime(value)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def datetime_values_equivalent(a, b):
    try:
        return parse_iso_datetime(a).astimezone(timezone.utc) == parse_iso_datetime(b).astimezone(timezone.utc)
    except Exception:
        return False


def salesforce_object_type_from_id(record_id):
    if not record_id:
        return None

    prefix = str(record_id)[:3]
    return {
        "001": "Account",
        "003": "Contact",
        "006": "Opportunity",
        "00Q": "Lead",
        "00U": "Event",
        "00T": "Task",
    }.get(prefix, "Record")


def clamp_limit(value, default=25, maximum=100):
    try:
        value = int(value)
    except Exception:
        return default

    return max(1, min(value, maximum))


def values_equivalent(a, b):
    if a is None and b is None:
        return True

    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)

    if isinstance(a, str) and isinstance(b, str):
        if ("T" in a and (a.endswith("Z") or "+" in a[-6:] or a[-5:-4] == "-")) and (
            "T" in b and (b.endswith("Z") or "+" in b[-6:] or b[-5:-4] == "-")
        ):
            if datetime_values_equivalent(a, b):
                return True

    return str(a) == str(b)


# ============================================================
# CRM FORMATTERS
# ============================================================

def format_account(account):
    if not account:
        return None

    return {
        "id": account.get("Id"),
        "name": account.get("Name"),
        "industry": account.get("Industry"),
        "website": account.get("Website"),
        "phone": account.get("Phone"),

        "billing_address": {
            "street": account.get("BillingStreet"),
            "city": account.get("BillingCity"),
            "state": account.get("BillingState"),
            "postal_code": account.get("BillingPostalCode"),
            "country": account.get("BillingCountry"),
            "latitude": account.get("BillingLatitude"),
            "longitude": account.get("BillingLongitude"),
        },

        "shipping_address": {
            "street": account.get("ShippingStreet"),
            "city": account.get("ShippingCity"),
            "state": account.get("ShippingState"),
            "postal_code": account.get("ShippingPostalCode"),
            "country": account.get("ShippingCountry"),
            "latitude": account.get("ShippingLatitude"),
            "longitude": account.get("ShippingLongitude"),
        },
    }


def format_contact(contact):
    if not contact:
        return None

    return {
        "id": contact.get("Id"),
        "first_name": contact.get("FirstName"),
        "last_name": contact.get("LastName"),
        "name": contact.get("Name"),
        "title": contact.get("Title"),
        "department": contact.get("Department"),
        "email": contact.get("Email"),
        "phone": contact.get("Phone"),
        "mobile": contact.get("MobilePhone"),
        "account_id": contact.get("AccountId"),

        "mailing_address": {
            "street": contact.get("MailingStreet"),
            "city": contact.get("MailingCity"),
            "state": contact.get("MailingState"),
            "postal_code": contact.get("MailingPostalCode"),
            "country": contact.get("MailingCountry"),
            "latitude": contact.get("MailingLatitude"),
            "longitude": contact.get("MailingLongitude"),
        },

        "account": format_account(contact.get("Account")),
    }


# ============================================================
# LOCATION + DEMO GEOGRAPHY ADAPTER
# ============================================================

# Demo fallback centers. When Salesforce Accounts have coordinates, those are
# preferred and these centers are used only to group/select a useful territory.
DEMO_GEO_CENTERS = [
    {"key": "dallas", "label": "Dallas, TX", "latitude": 32.7767, "longitude": -96.7970},
    {"key": "chicago", "label": "Chicago, IL", "latitude": 41.8781, "longitude": -87.6298},
    {"key": "boston", "label": "Boston, MA", "latitude": 42.3601, "longitude": -71.0589},
    {"key": "sf", "label": "San Francisco, CA", "latitude": 37.7749, "longitude": -122.4194},
]

DEMO_FORCE_CENTERS = DEMO_GEO_CENTERS + [
    {"key": "houston", "label": "Houston, TX", "latitude": 29.7604, "longitude": -95.3698},
    {"key": "austin", "label": "Austin, TX", "latitude": 30.2672, "longitude": -97.7431},
    {"key": "sandiego", "label": "San Diego, CA", "latitude": 32.7157, "longitude": -117.1611},
    {"key": "losangeles", "label": "Los Angeles, CA", "latitude": 34.0522, "longitude": -118.2437},
]

DEMO_CITY_COORDS = {
    ("dallas", "tx"): (32.7767, -96.7970),
    ("austin", "tx"): (30.2672, -97.7431),
    ("houston", "tx"): (29.7604, -95.3698),
    ("chicago", "il"): (41.8781, -87.6298),
    ("boston", "ma"): (42.3601, -71.0589),
    ("cambridge", "ma"): (42.3736, -71.1097),
    ("waltham", "ma"): (42.3765, -71.2356),
    ("san francisco", "ca"): (37.7749, -122.4194),
    ("san diego", "ca"): (32.7157, -117.1611),
    ("los angeles", "ca"): (34.0522, -118.2437),
}


def haversine_km(lat1, lon1, lat2, lon2):
    radius = 6371.0088
    p1 = math.radians(float(lat1))
    p2 = math.radians(float(lat2))
    dp = math.radians(float(lat2) - float(lat1))
    dl = math.radians(float(lon2) - float(lon1))
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def account_coordinates(account):
    if not account:
        return None
    for key in ("billing_address", "shipping_address"):
        address = account.get(key) or {}
        lat = address.get("latitude")
        lon = address.get("longitude")
        if lat is not None and lon is not None:
            try:
                return float(lat), float(lon)
            except Exception:
                pass

    for key in ("billing_address", "shipping_address"):
        address = account.get(key) or {}
        city = str(address.get("city") or "").strip().lower()
        state = str(address.get("state") or "").strip().lower()
        if (city, state) in DEMO_CITY_COORDS:
            return DEMO_CITY_COORDS[(city, state)]
    return None


def location_label(location):
    if not location:
        return None
    city = str(location.get("city") or "").strip()
    region = str(location.get("region") or location.get("state") or "").strip()
    country = str(location.get("country") or "").strip()
    return ", ".join([x for x in (city, region, country) if x]) or None


def get_scoped_account_geo_rows(sf, salesforce_username):
    result = tool_search_opportunities(
        sf,
        salesforce_username,
        {
            "name_contains": None,
            "account_name_contains": None,
            "status": "open",
            "stage": None,
            "min_amount": None,
            "max_amount": None,
            "close_date_from": None,
            "close_date_to": None,
            "account_city": None,
            "account_state": None,
            "account_country": None,
            "include_contacts": False,
            "limit": 100,
        },
    )
    seen = {}
    for opp in result.get("opportunities", []):
        account = opp.get("account") or {}
        account_id = account.get("id")
        coords = account_coordinates(account)
        if not account_id or not coords:
            continue
        if account_id not in seen:
            seen[account_id] = {"account": account, "coords": coords}
    return list(seen.values())


def choose_demo_cluster(account_rows, stable_key):
    populated = {}
    for row in account_rows:
        lat, lon = row["coords"]
        center = min(
            DEMO_GEO_CENTERS,
            key=lambda c: haversine_km(lat, lon, c["latitude"], c["longitude"]),
        )
        populated.setdefault(center["key"], {"center": center, "rows": []})["rows"].append(row)

    clusters = sorted(populated.values(), key=lambda c: c["center"]["key"])
    if not clusters:
        clusters = [{"center": center, "rows": []} for center in DEMO_GEO_CENTERS]

    digest = hashlib.sha256(str(stable_key or "cmd-sally-demo").encode("utf-8")).digest()
    chosen = clusters[int.from_bytes(digest[:4], "big") % len(clusters)]

    if chosen["rows"]:
        lat = sum(r["coords"][0] for r in chosen["rows"]) / len(chosen["rows"])
        lon = sum(r["coords"][1] for r in chosen["rows"]) / len(chosen["rows"])
    else:
        lat = chosen["center"]["latitude"]
        lon = chosen["center"]["longitude"]

    return {
        "latitude": lat,
        "longitude": lon,
        "label": chosen["center"]["label"],
        "cluster": chosen["center"]["key"],
    }


def resolve_location_context(sf, salesforce_username, client_context, claims=None):
    raw = (client_context or {}).get("location") or {}
    try:
        actual_lat = float(raw.get("latitude"))
        actual_lon = float(raw.get("longitude"))
    except Exception:
        return None

    actual = {
        "latitude": actual_lat,
        "longitude": actual_lon,
        "accuracy_m": raw.get("accuracy_m"),
        "city": raw.get("city"),
        "region": raw.get("region"),
        "country": raw.get("country"),
        "iso_country_code": raw.get("iso_country_code"),
        "label": location_label(raw),
        "captured_at": raw.get("captured_at"),
    }

    account_rows = get_scoped_account_geo_rows(sf, salesforce_username)
    nearest_distance = None
    if account_rows:
        nearest_distance = min(
            haversine_km(actual_lat, actual_lon, row["coords"][0], row["coords"][1])
            for row in account_rows
        )

    use_demo = bool(feature_enabled("demo_geography", DEMO_GEO_ENABLED) and (nearest_distance is None or nearest_distance > DEMO_GEO_REAL_RADIUS_KM))
    if use_demo:
        forced_cluster = get_config_setting("demo_geo_force_cluster", "automatic")
        if forced_cluster and forced_cluster != "automatic":
            center = next((c for c in DEMO_FORCE_CENTERS if c["key"] == forced_cluster), None)
            if center:
                matching = []
                for row in account_rows:
                    lat, lon = row["coords"]
                    closest = min(DEMO_FORCE_CENTERS, key=lambda c: haversine_km(lat, lon, c["latitude"], c["longitude"]))
                    if closest["key"] == forced_cluster:
                        matching.append(row)
                if matching:
                    effective = {
                        "latitude": sum(r["coords"][0] for r in matching) / len(matching),
                        "longitude": sum(r["coords"][1] for r in matching) / len(matching),
                        "label": center["label"], "cluster": center["key"],
                    }
                else:
                    effective = {"latitude": center["latitude"], "longitude": center["longitude"], "label": center["label"], "cluster": center["key"]}
            else:
                stable_key = (client_context or {}).get("geo_session_id") or (claims or {}).get("oid") or salesforce_username
                effective = choose_demo_cluster(account_rows, stable_key)
        else:
            stable_key = (client_context or {}).get("geo_session_id") or (claims or {}).get("oid") or salesforce_username
            effective = choose_demo_cluster(account_rows, stable_key)
        effective["country"] = "USA"
        mode = "demo"
    else:
        effective = {
            "latitude": actual_lat,
            "longitude": actual_lon,
            "label": actual.get("label") or "Current location",
            "country": actual.get("country"),
        }
        mode = "real"

    return {
        "mode": mode,
        "demo_enabled": feature_enabled("demo_geography", DEMO_GEO_ENABLED),
        "actual": actual,
        "effective": effective,
        "nearest_scoped_account_km_from_actual": (
            round(nearest_distance, 1) if nearest_distance is not None else None
        ),
    }


def location_prompt(location_context):
    if not location_context:
        return "No current device location is available."
    actual = location_context.get("actual") or {}
    effective = location_context.get("effective") or {}
    return (
        "Location context for this request:\n"
        f"- mode: {location_context.get('mode')}\n"
        f"- actual device location: {actual.get('label') or (str(actual.get('latitude')) + ', ' + str(actual.get('longitude')))}\n"
        f"- effective CRM location: {effective.get('label') or (str(effective.get('latitude')) + ', ' + str(effective.get('longitude')))}\n"
        "Use the effective CRM location for nearby-account/customer workflows. "
        "If mode=demo, be transparent that the CRM geography is a demo translation."
    )


def tool_find_nearby_accounts(sf, salesforce_username, args, location_context):
    if not location_context or not (location_context.get("effective") or {}).get("latitude"):
        return {"ok": False, "error": "No usable device/effective location is available."}

    radius_km = float(args.get("radius_km") or 50)
    radius_km = max(1.0, min(radius_km, 300.0))
    limit = clamp_limit(args.get("limit"), default=10, maximum=25)
    effective = location_context["effective"]

    opp_result = tool_search_opportunities(
        sf,
        salesforce_username,
        {
            "name_contains": None,
            "account_name_contains": None,
            "status": "open",
            "stage": None,
            "min_amount": None,
            "max_amount": None,
            "close_date_from": None,
            "close_date_to": None,
            "account_city": None,
            "account_state": None,
            "account_country": None,
            "include_contacts": True,
            "limit": 100,
        },
    )

    grouped = {}
    for opp in opp_result.get("opportunities", []):
        account = opp.get("account") or {}
        account_id = account.get("id")
        coords = account_coordinates(account)
        if not account_id or not coords:
            continue
        distance = haversine_km(effective["latitude"], effective["longitude"], coords[0], coords[1])
        if distance > radius_km:
            continue

        bucket = grouped.setdefault(account_id, {
            "account": account,
            "distance_km": distance,
            "open_pipeline": 0.0,
            "opportunities": [],
            "contacts": [],
        })
        bucket["distance_km"] = min(bucket["distance_km"], distance)
        bucket["open_pipeline"] += float(opp.get("amount") or 0)
        bucket["opportunities"].append({
            "id": opp.get("id"),
            "name": opp.get("name"),
            "stage": opp.get("stage"),
            "amount": opp.get("amount"),
            "close_date": opp.get("close_date"),
            "next_step": opp.get("next_step"),
        })
        for role in opp.get("contacts") or []:
            contact = role.get("contact") or {}
            if contact.get("id") and not any(c.get("id") == contact.get("id") for c in bucket["contacts"]):
                bucket["contacts"].append({
                    "id": contact.get("id"),
                    "name": contact.get("name"),
                    "title": contact.get("title"),
                    "phone": contact.get("mobile") or contact.get("phone"),
                    "email": contact.get("email"),
                    "role": role.get("role"),
                    "is_primary": role.get("is_primary"),
                })

    rows = list(grouped.values())
    for row in rows:
        row["distance_km"] = round(row["distance_km"], 1)
        row["distance_miles"] = round(row["distance_km"] * 0.621371, 1)
        row["opportunities"].sort(key=lambda o: -(float(o.get("amount") or 0)))
        row["top_opportunity"] = row["opportunities"][0] if row["opportunities"] else None
    rows.sort(key=lambda r: (r["distance_km"], -r["open_pipeline"]))
    rows = rows[:limit]

    return {
        "ok": True,
        "count": len(rows),
        "radius_km": radius_km,
        "location_context": location_context,
        "nearby_accounts": rows,
    }


# ============================================================
# CRM READ TOOLS
# ============================================================

def tool_search_opportunities(sf, salesforce_username, args):
    """Safe, Salesforce-native Opportunity query planner.

    Luna chooses structured filters/sort/aggregation; the backend owns SOQL.
    This deliberately does not accept raw SOQL from the model.
    """
    username = soql_escape(salesforce_username)
    status = args.get("status", "all")
    limit = clamp_limit(args.get("limit"), default=25)
    include_contacts = bool(args.get("include_contacts"))
    include_comments = bool(args.get("include_comments"))
    aggregate = args.get("aggregate") or "none"
    group_by = args.get("group_by") or "none"

    where = [f"Owner.Username = '{username}'"]

    if status == "open":
        where.append("IsClosed = false")
    elif status == "closed_won":
        where.append("IsWon = true")
    elif status == "closed_lost":
        where.append("IsClosed = true AND IsWon = false")

    if args.get("overdue"):
        where.append("IsClosed = false")
        where.append("CloseDate < TODAY")

    if args.get("name_contains"):
        where.append(f"Name LIKE '%{soql_like_escape(args['name_contains'])}%'")
    if args.get("account_name_contains"):
        where.append(f"Account.Name LIKE '%{soql_like_escape(args['account_name_contains'])}%'")
    if args.get("stage"):
        where.append(f"StageName = '{soql_escape(args['stage'])}'")
    if args.get("stage_in"):
        vals = [f"'{soql_escape(v)}'" for v in args.get("stage_in") if v]
        if vals:
            where.append("StageName IN (" + ",".join(vals) + ")")
    if args.get("add_to_forecast"):
        where.append(f"Add_to_Forecast__c = '{soql_escape(args['add_to_forecast'])}'")
    if args.get("confidence_levels"):
        vals = [f"'{soql_escape(v)}'" for v in args.get("confidence_levels") if v]
        if vals:
            where.append("Confidence_Level__c IN (" + ",".join(vals) + ")")
    if args.get("primary_product_contains"):
        where.append(f"Primary_Product__c LIKE '%{soql_like_escape(args['primary_product_contains'])}%'")
    if args.get("min_amount") is not None:
        where.append(f"Amount >= {float(args['min_amount'])}")
    if args.get("max_amount") is not None:
        where.append(f"Amount <= {float(args['max_amount'])}")

    relative = args.get("close_date_relative")
    allowed_relative = {
        "YESTERDAY", "TODAY", "TOMORROW", "LAST_WEEK", "THIS_WEEK", "NEXT_WEEK",
        "LAST_MONTH", "THIS_MONTH", "NEXT_MONTH", "LAST_QUARTER", "THIS_QUARTER",
        "NEXT_QUARTER", "LAST_YEAR", "THIS_YEAR", "NEXT_YEAR",
    }
    if relative:
        if relative not in allowed_relative:
            raise ValueError("Unsupported Salesforce relative date literal.")
        where.append(f"CloseDate = {relative}")
    else:
        if args.get("close_date_from"):
            where.append(f"CloseDate >= {validate_iso_date(args['close_date_from'])}")
        if args.get("close_date_to"):
            where.append(f"CloseDate <= {validate_iso_date(args['close_date_to'])}")

    if args.get("account_city"):
        where.append(f"Account.BillingCity = '{soql_escape(args['account_city'])}'")
    if args.get("account_state"):
        state = str(args["account_state"]).strip()
        if re.fullmatch(r"[A-Za-z]{2}", state):
            where.append(f"Account.BillingStateCode = '{soql_escape(state.upper())}'")
        else:
            where.append(f"Account.BillingState = '{soql_escape(state)}'")
    if args.get("account_country"):
        country = str(args["account_country"]).strip()
        if len(country) == 2:
            where.append(f"Account.BillingCountryCode = '{soql_escape(country.upper())}'")
        else:
            where.append(f"Account.BillingCountry = '{soql_escape(country)}'")

    if aggregate != "none":
        aggregate_map = {
            "count": "COUNT(Id)",
            "sum_amount": "SUM(Amount)",
            "avg_amount": "AVG(Amount)",
            "max_amount": "MAX(Amount)",
            "min_amount": "MIN(Amount)",
        }
        group_map = {
            "stage": "StageName",
            "account": "Account.Name",
            "state": "Account.BillingState",
            "add_to_forecast": "Add_to_Forecast__c",
            "confidence": "Confidence_Level__c",
            "primary_product": "Primary_Product__c",
        }
        if aggregate not in aggregate_map:
            raise ValueError("Unsupported Opportunity aggregation.")
        group_field = group_map.get(group_by)
        select_parts = []
        if group_field:
            select_parts.append(group_field)
        select_parts.append(aggregate_map[aggregate])
        soql = "SELECT " + ", ".join(select_parts) + " FROM Opportunity WHERE " + " AND ".join(where)
        if group_field:
            soql += f" GROUP BY {group_field}"
        soql += f" LIMIT {limit}"
        data = salesforce_query(sf["access_token"], sf["instance_url"], soql)
        rows = []
        for row in data.get("records", []):
            if group_field == "Account.Name":
                group_value = (row.get("Account") or {}).get("Name")
            else:
                group_value = row.get(group_field) if group_field else None
            rows.append({
                "group": group_value,
                "value": row.get("expr0"),
                "aggregate": aggregate,
            })
        return {"ok": True, "count": len(rows), "aggregate": aggregate, "group_by": group_by, "summary_rows": rows}

    fields = [
        "Id", "Name", "StageName", "Amount", "CloseDate", "Probability", "NextStep",
        "Type", "LeadSource", "ForecastCategoryName", "Description", "IsClosed", "IsWon",
        "LastActivityDate", "AccountId", "SFDC_Project_No__c", "Primary_Product__c",
        "Confidence_Level__c", "Add_to_Forecast__c",
        "Account.Id", "Account.Name", "Account.Industry", "Account.Website", "Account.Phone",
        "Account.BillingStreet", "Account.BillingCity", "Account.BillingState", "Account.BillingStateCode",
        "Account.BillingPostalCode", "Account.BillingCountry", "Account.BillingCountryCode",
        "Account.BillingLatitude", "Account.BillingLongitude", "Account.ShippingStreet",
        "Account.ShippingCity", "Account.ShippingState", "Account.ShippingPostalCode",
        "Account.ShippingCountry", "Account.ShippingLatitude", "Account.ShippingLongitude",
    ]
    if include_comments:
        fields.append("Comments__c")
    if include_contacts:
        fields.append("""(
            SELECT Id, ContactId, Role, IsPrimary, Contact.Id, Contact.FirstName, Contact.LastName,
                   Contact.Name, Contact.Title, Contact.Department, Contact.Email, Contact.Phone,
                   Contact.MobilePhone, Contact.MailingStreet, Contact.MailingCity, Contact.MailingState,
                   Contact.MailingPostalCode, Contact.MailingCountry, Contact.MailingLatitude,
                   Contact.MailingLongitude
            FROM OpportunityContactRoles
        )""")

    sort_map = {
        "close_date": "CloseDate", "amount": "Amount", "name": "Name", "stage": "StageName",
        "last_activity": "LastActivityDate", "confidence": "Confidence_Level__c",
    }
    sort_field = sort_map.get(args.get("sort_by") or "close_date", "CloseDate")
    direction = "DESC" if str(args.get("sort_direction") or "ASC").upper() == "DESC" else "ASC"
    soql = "SELECT " + ", ".join(fields) + " FROM Opportunity WHERE " + " AND ".join(where)
    soql += f" ORDER BY {sort_field} {direction} NULLS LAST LIMIT {limit}"

    data = salesforce_query(sf["access_token"], sf["instance_url"], soql)
    opportunities = []
    for row in data.get("records", []):
        contacts = []
        if include_contacts:
            contact_roles = row.get("OpportunityContactRoles") or {}
            for role in contact_roles.get("records", []):
                contacts.append({
                    "role": role.get("Role"),
                    "is_primary": role.get("IsPrimary"),
                    "contact": format_contact(role.get("Contact")),
                })
            contacts.sort(key=lambda role: (not bool(role.get("is_primary")), str((role.get("contact") or {}).get("name") or "")))

        opportunities.append({
            "id": row.get("Id"), "name": row.get("Name"), "project_number": row.get("SFDC_Project_No__c"),
            "stage": row.get("StageName"), "amount": row.get("Amount"), "close_date": row.get("CloseDate"),
            "probability": row.get("Probability"), "confidence_level": row.get("Confidence_Level__c"),
            "add_to_forecast": row.get("Add_to_Forecast__c"), "primary_product": row.get("Primary_Product__c"),
            "next_step": row.get("NextStep"), "type": row.get("Type"), "lead_source": row.get("LeadSource"),
            "forecast_category": row.get("ForecastCategoryName"), "description": row.get("Description"),
            "comments": row.get("Comments__c") if include_comments else None,
            "last_activity_date": row.get("LastActivityDate"), "is_closed": row.get("IsClosed"),
            "is_won": row.get("IsWon"), "account": format_account(row.get("Account")), "contacts": contacts,
            "primary_contact": next((r.get("contact") for r in contacts if r.get("is_primary")), None),
        })
    return {"ok": True, "count": len(opportunities), "opportunities": opportunities}

def tool_search_contacts(sf, salesforce_username, args):
    username = soql_escape(salesforce_username)
    limit = clamp_limit(args.get("limit"), default=25)

    fields = [
        "Id",
        "FirstName",
        "LastName",
        "Name",
        "Title",
        "Department",
        "Email",
        "Phone",
        "MobilePhone",
        "AccountId",

        "MailingStreet",
        "MailingCity",
        "MailingState",
        "MailingPostalCode",
        "MailingCountry",
        "MailingLatitude",
        "MailingLongitude",

        "Account.Id",
        "Account.Name",
        "Account.Industry",
        "Account.Website",
        "Account.Phone",

        "Account.BillingStreet",
        "Account.BillingCity",
        "Account.BillingState",
        "Account.BillingPostalCode",
        "Account.BillingCountry",
        "Account.BillingLatitude",
        "Account.BillingLongitude",

        "Account.ShippingStreet",
        "Account.ShippingCity",
        "Account.ShippingState",
        "Account.ShippingPostalCode",
        "Account.ShippingCountry",
        "Account.ShippingLatitude",
        "Account.ShippingLongitude",
    ]

    where = [
        (
            "AccountId IN "
            "("
            "SELECT AccountId "
            "FROM Opportunity "
            f"WHERE Owner.Username = '{username}'"
            ")"
        )
    ]

    if args.get("name_contains"):
        value = soql_like_escape(args["name_contains"])
        where.append(f"Name LIKE '%{value}%'")

    if args.get("title_contains"):
        value = soql_like_escape(args["title_contains"])
        where.append(f"Title LIKE '%{value}%'")

    if args.get("account_name_contains"):
        value = soql_like_escape(args["account_name_contains"])
        where.append(f"Account.Name LIKE '%{value}%'")

    if args.get("account_city"):
        value = soql_escape(args["account_city"])
        where.append(f"Account.BillingCity = '{value}'")

    if args.get("account_state"):
        value = soql_escape(args["account_state"])
        where.append(f"Account.BillingState = '{value}'")

    if args.get("account_country"):
        value = soql_escape(args["account_country"])
        where.append(f"Account.BillingCountry = '{value}'")

    soql = (
        "SELECT "
        + ", ".join(fields)
        + " FROM Contact "
        + "WHERE "
        + " AND ".join(where)
        + " ORDER BY LastName ASC "
        + f"LIMIT {limit}"
    )

    data = salesforce_query(
        sf["access_token"],
        sf["instance_url"],
        soql,
    )

    contacts = [
        format_contact(row)
        for row in data.get("records", [])
    ]

    return {
        "ok": True,
        "count": len(contacts),
        "contacts": contacts,
    }


def tool_search_accounts(sf, salesforce_username, args):
    username = soql_escape(salesforce_username)
    limit = clamp_limit(args.get("limit"), default=25)

    fields = [
        "Id",
        "Name",
        "Industry",
        "Website",
        "Phone",

        "BillingStreet",
        "BillingCity",
        "BillingState",
        "BillingPostalCode",
        "BillingCountry",
        "BillingLatitude",
        "BillingLongitude",

        "ShippingStreet",
        "ShippingCity",
        "ShippingState",
        "ShippingPostalCode",
        "ShippingCountry",
        "ShippingLatitude",
        "ShippingLongitude",
    ]

    where = [
        (
            "Id IN "
            "("
            "SELECT AccountId "
            "FROM Opportunity "
            f"WHERE Owner.Username = '{username}'"
            ")"
        )
    ]

    if args.get("name_contains"):
        value = soql_like_escape(args["name_contains"])
        where.append(f"Name LIKE '%{value}%'")

    if args.get("industry_contains"):
        value = soql_like_escape(args["industry_contains"])
        where.append(f"Industry LIKE '%{value}%'")

    if args.get("city"):
        value = soql_escape(args["city"])
        where.append(f"BillingCity = '{value}'")

    if args.get("state"):
        value = soql_escape(args["state"])
        where.append(f"BillingState = '{value}'")

    if args.get("country"):
        value = soql_escape(args["country"])
        where.append(f"BillingCountry = '{value}'")

    soql = (
        "SELECT "
        + ", ".join(fields)
        + " FROM Account "
        + "WHERE "
        + " AND ".join(where)
        + " ORDER BY Name ASC "
        + f"LIMIT {limit}"
    )

    data = salesforce_query(
        sf["access_token"],
        sf["instance_url"],
        soql,
    )

    accounts = [
        format_account(row)
        for row in data.get("records", [])
    ]

    return {
        "ok": True,
        "count": len(accounts),
        "accounts": accounts,
    }


# ============================================================
# SALESFORCE EVENT HELPERS + READ TOOL
# ============================================================

def format_event(row):
    if not row:
        return None

    who = row.get("Who") or {}
    what = row.get("What") or {}
    who_id = row.get("WhoId")
    what_id = row.get("WhatId")

    return {
        "id": row.get("Id"),
        "subject": row.get("Subject"),
        "start_datetime": row.get("StartDateTime"),
        "end_datetime": row.get("EndDateTime"),
        "activity_date": row.get("ActivityDate"),
        "is_all_day_event": row.get("IsAllDayEvent"),
        "location": row.get("Location"),
        "description": row.get("Description"),
        "who": {
            "id": who_id,
            "name": who.get("Name"),
            "type": salesforce_object_type_from_id(who_id),
        } if who_id else None,
        "what": {
            "id": what_id,
            "name": what.get("Name"),
            "type": salesforce_object_type_from_id(what_id),
        } if what_id else None,
        "owner": {
            "id": row.get("OwnerId"),
            "name": (row.get("Owner") or {}).get("Name"),
            "username": (row.get("Owner") or {}).get("Username"),
        },
    }


def tool_search_events(sf, salesforce_username, args):
    username = soql_escape(salesforce_username)
    limit = clamp_limit(args.get("limit"), default=25)
    related_name = (args.get("related_name_contains") or "").strip().lower()
    query_limit = min(100, max(limit, 75 if related_name else limit))

    fields = [
        "Id", "Subject", "StartDateTime", "EndDateTime", "ActivityDate", "IsAllDayEvent",
        "Location", "Description", "WhoId", "WhatId", "Who.Name", "What.Name",
        "OwnerId", "Owner.Name", "Owner.Username",
    ]
    where = [f"Owner.Username = '{username}'"]
    relative = args.get("start_relative")
    allowed_relative = {
        "YESTERDAY", "TODAY", "TOMORROW", "LAST_WEEK", "THIS_WEEK", "NEXT_WEEK",
        "LAST_MONTH", "THIS_MONTH", "NEXT_MONTH", "LAST_QUARTER", "THIS_QUARTER",
        "NEXT_QUARTER", "LAST_YEAR", "THIS_YEAR", "NEXT_YEAR",
    }
    if relative:
        if relative not in allowed_relative:
            raise ValueError("Unsupported Salesforce relative date literal.")
        where.append(f"StartDateTime = {relative}")
    else:
        if args.get("start_datetime_from"):
            where.append("StartDateTime >= " + salesforce_soql_datetime(args["start_datetime_from"]))
        if args.get("start_datetime_to"):
            where.append("StartDateTime <= " + salesforce_soql_datetime(args["start_datetime_to"]))
    if args.get("time_scope") == "upcoming":
        where.append("StartDateTime >= TODAY")
    elif args.get("time_scope") == "past":
        where.append("StartDateTime < TODAY")
    if args.get("subject_contains"):
        where.append(f"Subject LIKE '%{soql_like_escape(args['subject_contains'])}%'")

    soql = "SELECT " + ", ".join(fields) + " FROM Event WHERE " + " AND ".join(where)
    soql += f" ORDER BY StartDateTime ASC LIMIT {query_limit}"
    data = salesforce_query(sf["access_token"], sf["instance_url"], soql)
    events = [format_event(row) for row in data.get("records", [])]
    if related_name:
        events = [
            event for event in events
            if related_name in str((event.get("who") or {}).get("name") or "").lower()
            or related_name in str((event.get("what") or {}).get("name") or "").lower()
            or related_name in str(event.get("subject") or "").lower()
        ]
    return {"ok": True, "count": len(events[:limit]), "events": events[:limit]}


def format_task(row):
    if not row:
        return None
    who_id = row.get("WhoId")
    what_id = row.get("WhatId")
    return {
        "id": row.get("Id"),
        "subject": row.get("Subject"),
        "activity_date": row.get("ActivityDate"),
        "status": row.get("Status"),
        "priority": row.get("Priority"),
        "description": row.get("Description"),
        "is_closed": row.get("IsClosed"),
        "who": {"id": who_id, "name": (row.get("Who") or {}).get("Name"), "type": salesforce_object_type_from_id(who_id)} if who_id else None,
        "what": {"id": what_id, "name": (row.get("What") or {}).get("Name"), "type": salesforce_object_type_from_id(what_id)} if what_id else None,
        "owner": {"id": row.get("OwnerId"), "name": (row.get("Owner") or {}).get("Name"), "username": (row.get("Owner") or {}).get("Username")},
    }


def tool_search_tasks(sf, salesforce_username, args):
    username = soql_escape(salesforce_username)
    limit = clamp_limit(args.get("limit"), default=25)
    related_name = (args.get("related_name_contains") or "").strip().lower()
    query_limit = min(100, max(limit, 75 if related_name else limit))
    fields = ["Id", "Subject", "ActivityDate", "Status", "Priority", "Description", "IsClosed", "WhoId", "WhatId", "Who.Name", "What.Name", "OwnerId", "Owner.Name", "Owner.Username"]
    where = [f"Owner.Username = '{username}'"]
    task_status = args.get("task_status") or "all"
    if task_status == "open": where.append("IsClosed = false")
    elif task_status == "completed": where.append("IsClosed = true")
    if args.get("overdue"):
        where.extend(["IsClosed = false", "ActivityDate < TODAY"])
    relative = args.get("date_relative")
    allowed_relative = {"YESTERDAY", "TODAY", "TOMORROW", "LAST_WEEK", "THIS_WEEK", "NEXT_WEEK", "LAST_MONTH", "THIS_MONTH", "NEXT_MONTH", "LAST_QUARTER", "THIS_QUARTER", "NEXT_QUARTER", "LAST_YEAR", "THIS_YEAR", "NEXT_YEAR"}
    if relative:
        if relative not in allowed_relative: raise ValueError("Unsupported Salesforce relative date literal.")
        where.append(f"ActivityDate = {relative}")
    else:
        if args.get("date_from"): where.append(f"ActivityDate >= {validate_iso_date(args['date_from'])}")
        if args.get("date_to"): where.append(f"ActivityDate <= {validate_iso_date(args['date_to'])}")
    if args.get("subject_contains"):
        where.append(f"Subject LIKE '%{soql_like_escape(args['subject_contains'])}%'")
    soql = "SELECT " + ", ".join(fields) + " FROM Task WHERE " + " AND ".join(where) + f" ORDER BY ActivityDate ASC NULLS LAST LIMIT {query_limit}"
    data = salesforce_query(sf["access_token"], sf["instance_url"], soql)
    tasks = [format_task(row) for row in data.get("records", [])]
    if related_name:
        tasks = [t for t in tasks if related_name in str((t.get("who") or {}).get("name") or "").lower() or related_name in str((t.get("what") or {}).get("name") or "").lower() or related_name in str(t.get("subject") or "").lower()]
    return {"ok": True, "count": len(tasks[:limit]), "tasks": tasks[:limit]}


def tool_get_opportunity_context(sf, salesforce_username, args):
    opp_id = str(args.get("opportunity_id") or "").strip()
    if not re.fullmatch(r"006[A-Za-z0-9]{12,15}", opp_id):
        raise ValueError("A valid Salesforce Opportunity Id is required.")
    safe_username = soql_escape(salesforce_username)
    safe_id = soql_escape(opp_id)
    soql = f"""SELECT Id,Name,SFDC_Project_No__c,StageName,Amount,CloseDate,Probability,NextStep,
        ForecastCategoryName,Primary_Product__c,Confidence_Level__c,Add_to_Forecast__c,Comments__c,
        Description,LastActivityDate,IsClosed,IsWon,Account.Id,Account.Name,Account.Industry,Account.Website,
        Account.Phone,Account.BillingStreet,Account.BillingCity,Account.BillingState,Account.BillingStateCode,
        Account.BillingPostalCode,Account.BillingCountry,Account.BillingLatitude,Account.BillingLongitude,
        (SELECT Id,Role,IsPrimary,Contact.Id,Contact.Name,Contact.Title,Contact.Department,Contact.Email,Contact.Phone,Contact.MobilePhone FROM OpportunityContactRoles)
        FROM Opportunity WHERE Id='{safe_id}' AND Owner.Username='{safe_username}' LIMIT 1"""
    records = salesforce_query(sf["access_token"], sf["instance_url"], " ".join(soql.split())).get("records", [])
    if not records: raise ValueError("Opportunity not found in the authenticated user's scope.")
    row = records[0]
    roles=[]
    for role in (row.get("OpportunityContactRoles") or {}).get("records", []):
        roles.append({"role":role.get("Role"),"is_primary":role.get("IsPrimary"),"contact":format_contact(role.get("Contact"))})
    roles.sort(key=lambda r:(not bool(r.get("is_primary")), str((r.get("contact") or {}).get("name") or "")))
    opportunity={
        "id":row.get("Id"),"name":row.get("Name"),"project_number":row.get("SFDC_Project_No__c"),"stage":row.get("StageName"),
        "amount":row.get("Amount"),"close_date":row.get("CloseDate"),"probability":row.get("Probability"),"next_step":row.get("NextStep"),
        "forecast_category":row.get("ForecastCategoryName"),"primary_product":row.get("Primary_Product__c"),"confidence_level":row.get("Confidence_Level__c"),
        "add_to_forecast":row.get("Add_to_Forecast__c"),"comments":row.get("Comments__c"),"description":row.get("Description"),"last_activity_date":row.get("LastActivityDate"),
        "is_closed":row.get("IsClosed"),"is_won":row.get("IsWon"),"account":format_account(row.get("Account")),"contacts":roles,
        "primary_contact":next((r.get("contact") for r in roles if r.get("is_primary")),None),
    }
    ev_soql = f"SELECT Id,Subject,StartDateTime,EndDateTime,ActivityDate,IsAllDayEvent,Location,Description,WhoId,WhatId,Who.Name,What.Name,OwnerId,Owner.Name,Owner.Username FROM Event WHERE Owner.Username='{safe_username}' AND WhatId='{safe_id}' ORDER BY StartDateTime DESC LIMIT 75"
    task_soql = f"SELECT Id,Subject,ActivityDate,Status,Priority,Description,IsClosed,WhoId,WhatId,Who.Name,What.Name,OwnerId,Owner.Name,Owner.Username FROM Task WHERE Owner.Username='{safe_username}' AND WhatId='{safe_id}' ORDER BY ActivityDate DESC NULLS LAST LIMIT 75"
    events=[format_event(r) for r in salesforce_query(sf["access_token"],sf["instance_url"],ev_soql).get("records",[])]
    tasks=[format_task(r) for r in salesforce_query(sf["access_token"],sf["instance_url"],task_soql).get("records",[])]
    return {"ok":True,"count":1,"opportunity":opportunity,"events":events,"tasks":tasks}

def get_scoped_related_record(sf, salesforce_username, record_id, expected_role):
    if not record_id:
        return None

    safe_username = soql_escape(salesforce_username)
    safe_id = soql_escape(record_id)
    object_type = salesforce_object_type_from_id(record_id)

    if expected_role == "who":
        if object_type != "Contact":
            raise ValueError(
                "For this pilot, Event WhoId may only reference a Salesforce Contact."
            )

        soql = (
            "SELECT Id, Name, AccountId, Account.Name FROM Contact "
            f"WHERE Id = '{safe_id}' AND AccountId IN ("
            "SELECT AccountId FROM Opportunity "
            f"WHERE Owner.Username = '{safe_username}'"
            ") LIMIT 1"
        )

    elif expected_role == "what":
        if object_type == "Opportunity":
            soql = (
                "SELECT Id, Name FROM Opportunity "
                f"WHERE Id = '{safe_id}' "
                f"AND Owner.Username = '{safe_username}' LIMIT 1"
            )
        elif object_type == "Account":
            soql = (
                "SELECT Id, Name FROM Account "
                f"WHERE Id = '{safe_id}' AND Id IN ("
                "SELECT AccountId FROM Opportunity "
                f"WHERE Owner.Username = '{safe_username}'"
                ") LIMIT 1"
            )
        else:
            raise ValueError(
                "For this pilot, Event WhatId may only reference an owned Opportunity "
                "or an Account connected to the user's opportunities."
            )
    else:
        raise ValueError("Unknown related-record role.")

    data = salesforce_query(sf["access_token"], sf["instance_url"], soql)
    records = data.get("records", [])

    if not records:
        raise ValueError(
            "The related Salesforce record was not found inside the authenticated user's CRM scope."
        )

    row = records[0]
    return {
        "id": row.get("Id"),
        "name": row.get("Name"),
        "type": object_type,
    }


def get_owned_event(sf, salesforce_username, event_id):
    safe_username = soql_escape(salesforce_username)
    safe_id = soql_escape(event_id)

    soql = (
        "SELECT Id, Subject, StartDateTime, EndDateTime, ActivityDate, "
        "IsAllDayEvent, Location, Description, WhoId, WhatId, Who.Name, "
        "What.Name, OwnerId, Owner.Name, Owner.Username "
        "FROM Event "
        f"WHERE Id = '{safe_id}' AND Owner.Username = '{safe_username}' LIMIT 1"
    )

    data = salesforce_query(sf["access_token"], sf["instance_url"], soql)
    records = data.get("records", [])

    if not records:
        raise ValueError(
            "Event was not found in the authenticated user's owned Salesforce events."
        )

    return format_event(records[0])


ALLOWED_EVENT_WRITE_FIELDS = {
    "Subject",
    "StartDateTime",
    "EndDateTime",
    "ActivityDate",
    "IsAllDayEvent",
    "Location",
    "Description",
    "WhoId",
    "WhatId",
}


def normalize_event_write_value(field_name, new_value):
    if field_name not in ALLOWED_EVENT_WRITE_FIELDS:
        raise ValueError(f"Event field {field_name} is not allowed for AI updates.")

    if field_name == "Subject":
        if not isinstance(new_value, str) or not new_value.strip():
            raise ValueError("Event Subject must be non-empty text.")
        return new_value.strip()

    if field_name in {"StartDateTime", "EndDateTime"}:
        if new_value is None:
            return None
        return normalize_salesforce_datetime(new_value)

    if field_name == "ActivityDate":
        if new_value is None:
            return None
        return validate_iso_date(new_value)

    if field_name == "IsAllDayEvent":
        if not isinstance(new_value, bool):
            raise ValueError("IsAllDayEvent must be true or false.")
        return new_value

    if field_name in {"Location", "Description"}:
        if new_value is None:
            return None
        if not isinstance(new_value, str):
            raise ValueError(f"{field_name} must be text or null.")
        return new_value.strip() if field_name == "Location" else new_value

    if field_name in {"WhoId", "WhatId"}:
        if new_value is None:
            return None
        if not isinstance(new_value, str) or len(new_value.strip()) < 15:
            raise ValueError(f"{field_name} must be a Salesforce record Id or null.")
        return new_value.strip()

    raise ValueError("Unsupported Event field.")


def validate_event_temporal_fields(fields):
    is_all_day = bool(fields.get("IsAllDayEvent"))

    if is_all_day:
        if not fields.get("ActivityDate"):
            raise ValueError("All-day Events require ActivityDate.")
        return

    start = fields.get("StartDateTime")
    end = fields.get("EndDateTime")

    if not start or not end:
        raise ValueError("Timed Events require both StartDateTime and EndDateTime.")

    if parse_iso_datetime(end) <= parse_iso_datetime(start):
        raise ValueError("Event EndDateTime must be after StartDateTime.")


def tool_propose_create_event(sf, salesforce_username, args):
    fields = {
        "Subject": normalize_event_write_value("Subject", args.get("subject")),
        "IsAllDayEvent": bool(args.get("is_all_day_event")),
    }

    optional_map = {
        "start_datetime": "StartDateTime",
        "end_datetime": "EndDateTime",
        "activity_date": "ActivityDate",
        "location": "Location",
        "description": "Description",
        "who_id": "WhoId",
        "what_id": "WhatId",
    }

    for arg_name, field_name in optional_map.items():
        value = args.get(arg_name)
        if value is not None:
            fields[field_name] = normalize_event_write_value(field_name, value)

    validate_event_temporal_fields(fields)

    who = get_scoped_related_record(
        sf, salesforce_username, fields.get("WhoId"), "who"
    ) if fields.get("WhoId") else None

    what = get_scoped_related_record(
        sf, salesforce_username, fields.get("WhatId"), "what"
    ) if fields.get("WhatId") else None

    action = {
        "action": "create_event",
        "event_subject": fields["Subject"],
        "fields": fields,
        "who": who,
        "what": what,
    }

    return {
        "ok": True,
        "status": "pending_confirmation",
        "message": (
            "The Event has NOT been created in Salesforce. "
            "It is queued for explicit user confirmation."
        ),
        "pending_action": action,
    }


def get_owned_event_field(sf, salesforce_username, event_id, field_name):
    if field_name not in ALLOWED_EVENT_WRITE_FIELDS:
        raise ValueError("Event field is not allowed.")

    safe_username = soql_escape(salesforce_username)
    safe_id = soql_escape(event_id)

    soql = (
        f"SELECT Id, Subject, {field_name} FROM Event "
        f"WHERE Id = '{safe_id}' AND Owner.Username = '{safe_username}' LIMIT 1"
    )

    data = salesforce_query(sf["access_token"], sf["instance_url"], soql)
    records = data.get("records", [])

    if not records:
        raise ValueError(
            "Event was not found in the authenticated user's owned Salesforce events."
        )

    row = records[0]
    return {
        "id": row.get("Id"),
        "subject": row.get("Subject"),
        "field_name": field_name,
        "current_value": row.get(field_name),
    }


def tool_propose_update_event(sf, salesforce_username, args):
    event_id = args["event_id"]
    field_name = args["field_name"]
    new_value = normalize_event_write_value(field_name, args.get("new_value"))

    current = get_owned_event_field(
        sf, salesforce_username, event_id, field_name
    )

    if field_name == "WhoId" and new_value:
        get_scoped_related_record(sf, salesforce_username, new_value, "who")
    elif field_name == "WhatId" and new_value:
        get_scoped_related_record(sf, salesforce_username, new_value, "what")

    action = {
        "action": "update_event",
        "event_id": current["id"],
        "event_subject": current["subject"],
        "field_name": field_name,
        "old_value": current["current_value"],
        "new_value": new_value,
    }

    return {
        "ok": True,
        "status": "pending_confirmation",
        "message": (
            "The Event update has NOT been written to Salesforce. "
            "It is queued for explicit user confirmation."
        ),
        "pending_action": action,
    }


# ============================================================
# SALESFORCE WRITE PROPOSAL TOOL
# ============================================================

ALLOWED_OPPORTUNITY_WRITE_FIELDS = {
    "StageName",
    "CloseDate",
    "NextStep",
    "Amount",
    "Probability",
    "Description",
}


def normalize_opportunity_write_value(field_name, new_value):
    if field_name not in ALLOWED_OPPORTUNITY_WRITE_FIELDS:
        raise ValueError(
            f"Field {field_name} is not allowed for AI updates."
        )

    if field_name == "StageName":
        if not isinstance(new_value, str) or not new_value.strip():
            raise ValueError("StageName must be a non-empty string.")
        return new_value.strip()

    if field_name == "CloseDate":
        if new_value is None:
            raise ValueError("CloseDate cannot be null.")
        return validate_iso_date(new_value)

    if field_name == "NextStep":
        if new_value is None:
            return None
        if not isinstance(new_value, str):
            raise ValueError("NextStep must be text or null.")
        return new_value.strip()

    if field_name == "Amount":
        if new_value is None:
            return None
        value = float(new_value)
        if value < 0:
            raise ValueError("Amount cannot be negative.")
        return value

    if field_name == "Probability":
        if new_value is None:
            return None
        value = float(new_value)
        if value < 0 or value > 100:
            raise ValueError("Probability must be between 0 and 100.")
        return value

    if field_name == "Description":
        if new_value is None:
            return None
        if not isinstance(new_value, str):
            raise ValueError("Description must be text or null.")
        return new_value

    raise ValueError("Unsupported opportunity field.")


def get_owned_opportunity_field(
    sf,
    salesforce_username,
    opportunity_id,
    field_name,
):
    if field_name not in ALLOWED_OPPORTUNITY_WRITE_FIELDS:
        raise ValueError("Field is not allowed.")

    safe_username = soql_escape(salesforce_username)
    safe_id = soql_escape(opportunity_id)

    soql = (
        f"SELECT Id, Name, {field_name} "
        "FROM Opportunity "
        f"WHERE Id = '{safe_id}' "
        f"AND Owner.Username = '{safe_username}' "
        "LIMIT 1"
    )

    data = salesforce_query(
        sf["access_token"],
        sf["instance_url"],
        soql,
    )

    records = data.get("records", [])

    if not records:
        raise ValueError(
            "Opportunity was not found in the authenticated user's owned records."
        )

    row = records[0]

    return {
        "id": row.get("Id"),
        "name": row.get("Name"),
        "field_name": field_name,
        "current_value": row.get(field_name),
    }


def tool_propose_update_opportunity(
    sf,
    salesforce_username,
    args,
):
    opportunity_id = args["opportunity_id"]
    field_name = args["field_name"]
    new_value = normalize_opportunity_write_value(
        field_name,
        args.get("new_value"),
    )

    current = get_owned_opportunity_field(
        sf,
        salesforce_username,
        opportunity_id,
        field_name,
    )

    action = {
        "action": "update_opportunity",
        "opportunity_id": current["id"],
        "opportunity_name": current["name"],
        "field_name": field_name,
        "old_value": current["current_value"],
        "new_value": new_value,
    }

    return {
        "ok": True,
        "status": "pending_confirmation",
        "message": (
            "The update has NOT been written to Salesforce. "
            "It is queued for explicit user confirmation."
        ),
        "pending_action": action,
    }


# ============================================================
# OPENAI FUNCTION TOOL DEFINITIONS
# ============================================================

CRM_READ_TOOLS = [
    {
        "type": "function",
        "name": "search_opportunities",
        "description": (
            "Run a SAFE Salesforce-native Opportunity query for the authenticated user. "
            "Use this instead of pulling a broad list into the model. It supports relative Salesforce "
            "date literals, overdue detection, rich CMD fields, sorting, grouping and aggregation. "
            "The backend builds SOQL; never invent raw SOQL."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "name_contains": {"type": ["string", "null"]},
                "account_name_contains": {"type": ["string", "null"]},
                "status": {"type": "string", "enum": ["all", "open", "closed_won", "closed_lost"]},
                "overdue": {"type": "boolean", "description": "Open Opportunities with CloseDate before TODAY."},
                "stage": {"type": ["string", "null"]},
                "stage_in": {"type": ["array", "null"], "items": {"type": "string"}},
                "add_to_forecast": {"type": ["string", "null"], "enum": ["Upside", "In", "Out", None]},
                "confidence_levels": {"type": ["array", "null"], "items": {"type": "string", "enum": ["0%", "10%", "25%", "50%", "75%", "90%", "100%"]}},
                "primary_product_contains": {"type": ["string", "null"]},
                "min_amount": {"type": ["number", "null"]},
                "max_amount": {"type": ["number", "null"]},
                "close_date_relative": {"type": ["string", "null"], "enum": ["YESTERDAY", "TODAY", "TOMORROW", "LAST_WEEK", "THIS_WEEK", "NEXT_WEEK", "LAST_MONTH", "THIS_MONTH", "NEXT_MONTH", "LAST_QUARTER", "THIS_QUARTER", "NEXT_QUARTER", "LAST_YEAR", "THIS_YEAR", "NEXT_YEAR", None]},
                "close_date_from": {"type": ["string", "null"], "description": "ISO date YYYY-MM-DD; use only when a relative date literal is not suitable."},
                "close_date_to": {"type": ["string", "null"], "description": "ISO date YYYY-MM-DD; use only when a relative date literal is not suitable."},
                "account_city": {"type": ["string", "null"]},
                "account_state": {"type": ["string", "null"]},
                "account_country": {"type": ["string", "null"]},
                "include_contacts": {"type": "boolean"},
                "include_comments": {"type": "boolean"},
                "sort_by": {"type": "string", "enum": ["close_date", "amount", "name", "stage", "last_activity", "confidence"]},
                "sort_direction": {"type": "string", "enum": ["ASC", "DESC"]},
                "aggregate": {"type": "string", "enum": ["none", "count", "sum_amount", "avg_amount", "max_amount", "min_amount"]},
                "group_by": {"type": "string", "enum": ["none", "stage", "account", "state", "add_to_forecast", "confidence", "primary_product"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "required": ["name_contains", "account_name_contains", "status", "overdue", "stage", "stage_in", "add_to_forecast", "confidence_levels", "primary_product_contains", "min_amount", "max_amount", "close_date_relative", "close_date_from", "close_date_to", "account_city", "account_state", "account_country", "include_contacts", "include_comments", "sort_by", "sort_direction", "aggregate", "group_by", "limit"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_opportunity_context",
        "description": "Load one owned Opportunity with CMD custom fields, primary/secondary Opportunity Contact Roles, Events and Tasks. Use for deal summaries, meeting preparation, history, risk analysis and CRM + web research after an Opportunity id is known.",
        "strict": True,
        "parameters": {"type": "object", "properties": {"opportunity_id": {"type": "string"}}, "required": ["opportunity_id"], "additionalProperties": False},
    },
    {
        "type": "function", "name": "search_contacts",
        "description": "Search Contacts belonging to Accounts connected to Opportunities owned by the authenticated Salesforce user. Returns callable phone/mobile fields, email, role/title and Account context.",
        "strict": True,
        "parameters": {"type":"object","properties":{"name_contains":{"type":["string","null"]},"title_contains":{"type":["string","null"]},"account_name_contains":{"type":["string","null"]},"account_city":{"type":["string","null"]},"account_state":{"type":["string","null"]},"account_country":{"type":["string","null"]},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["name_contains","title_contains","account_name_contains","account_city","account_state","account_country","limit"],"additionalProperties":False},
    },
    {
        "type": "function", "name": "search_accounts",
        "description": "Search customer Accounts associated with Opportunities owned by the authenticated Salesforce user.",
        "strict": True,
        "parameters": {"type":"object","properties":{"name_contains":{"type":["string","null"]},"industry_contains":{"type":["string","null"]},"city":{"type":["string","null"]},"state":{"type":["string","null"]},"country":{"type":["string","null"]},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["name_contains","industry_contains","city","state","country","limit"],"additionalProperties":False},
    },
    {
        "type": "function", "name": "find_nearby_accounts",
        "description": "Find customer Accounts with open Opportunities near the user's effective location. Backend computes distance deterministically.",
        "strict": True,
        "parameters": {"type":"object","properties":{"radius_km":{"type":"number","minimum":1,"maximum":300},"limit":{"type":"integer","minimum":1,"maximum":25}},"required":["radius_km","limit"],"additionalProperties":False},
    },
    {
        "type": "function", "name": "search_events",
        "description": "Query Salesforce Events owned by the authenticated user. Prefer Salesforce relative date literals for this week/month/quarter style calendar questions.",
        "strict": True,
        "parameters": {"type":"object","properties":{"start_relative":{"type":["string","null"],"enum":["YESTERDAY","TODAY","TOMORROW","LAST_WEEK","THIS_WEEK","NEXT_WEEK","LAST_MONTH","THIS_MONTH","NEXT_MONTH","LAST_QUARTER","THIS_QUARTER","NEXT_QUARTER","LAST_YEAR","THIS_YEAR","NEXT_YEAR",None]},"time_scope":{"type":"string","enum":["all","upcoming","past"]},"start_datetime_from":{"type":["string","null"]},"start_datetime_to":{"type":["string","null"]},"subject_contains":{"type":["string","null"]},"related_name_contains":{"type":["string","null"]},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["start_relative","time_scope","start_datetime_from","start_datetime_to","subject_contains","related_name_contains","limit"],"additionalProperties":False},
    },
    {
        "type": "function", "name": "search_tasks",
        "description": "Query Salesforce Tasks owned by the authenticated user, including open/completed/overdue Tasks and Salesforce relative date periods.",
        "strict": True,
        "parameters": {"type":"object","properties":{"task_status":{"type":"string","enum":["all","open","completed"]},"overdue":{"type":"boolean"},"date_relative":{"type":["string","null"],"enum":["YESTERDAY","TODAY","TOMORROW","LAST_WEEK","THIS_WEEK","NEXT_WEEK","LAST_MONTH","THIS_MONTH","NEXT_MONTH","LAST_QUARTER","THIS_QUARTER","NEXT_QUARTER","LAST_YEAR","THIS_YEAR","NEXT_YEAR",None]},"date_from":{"type":["string","null"]},"date_to":{"type":["string","null"]},"subject_contains":{"type":["string","null"]},"related_name_contains":{"type":["string","null"]},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["task_status","overdue","date_relative","date_from","date_to","subject_contains","related_name_contains","limit"],"additionalProperties":False},
    },
]


CRM_WRITE_TOOLS = [
    {
        "type": "function",
        "name": "propose_update_opportunity",
        "description": (
            "Propose changing ONE allowed field on an opportunity owned by "
            "the authenticated user. This tool NEVER writes immediately. "
            "It creates a pending change that requires explicit user confirmation."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "opportunity_id": {
                    "type": "string",
                    "description": "Salesforce Opportunity Id.",
                },
                "field_name": {
                    "type": "string",
                    "enum": [
                        "StageName",
                        "CloseDate",
                        "NextStep",
                        "Amount",
                        "Probability",
                        "Description",
                    ],
                },
                "new_value": {
                    "type": ["string", "number", "null"],
                    "description": (
                        "New value. CloseDate must be YYYY-MM-DD. "
                        "Probability must be 0-100."
                    ),
                },
            },
            "required": ["opportunity_id", "field_name", "new_value"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "propose_create_event",
        "description": (
            "Propose creating a Salesforce Event owned by the authenticated user. "
            "This NEVER creates the Event immediately. Timed events require start "
            "and end date-times with explicit timezone offsets. If the user gives a "
            "start time but no duration, use a 60-minute default unless context makes "
            "another duration clearly appropriate. WhoId is a Contact; WhatId may be "
            "an Account or Opportunity in the user's CRM scope."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "subject": {"type": "string"},
                "start_datetime": {"type": ["string", "null"]},
                "end_datetime": {"type": ["string", "null"]},
                "activity_date": {"type": ["string", "null"]},
                "is_all_day_event": {"type": "boolean"},
                "location": {"type": ["string", "null"]},
                "description": {"type": ["string", "null"]},
                "who_id": {"type": ["string", "null"]},
                "what_id": {"type": ["string", "null"]},
            },
            "required": [
                "subject",
                "start_datetime",
                "end_datetime",
                "activity_date",
                "is_all_day_event",
                "location",
                "description",
                "who_id",
                "what_id",
            ],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "propose_update_event",
        "description": (
            "Propose changing ONE allowed field on a Salesforce Event owned by the "
            "authenticated user. This NEVER writes immediately. For moving a timed "
            "meeting while preserving duration, normally propose both StartDateTime "
            "and EndDateTime as separate pending actions."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "event_id": {"type": "string"},
                "field_name": {
                    "type": "string",
                    "enum": [
                        "Subject",
                        "StartDateTime",
                        "EndDateTime",
                        "ActivityDate",
                        "IsAllDayEvent",
                        "Location",
                        "Description",
                        "WhoId",
                        "WhatId",
                    ],
                },
                "new_value": {
                    "type": ["string", "boolean", "null"],
                },
            },
            "required": ["event_id", "field_name", "new_value"],
            "additionalProperties": False,
        },
    },
]


# ============================================================
# CRM FUNCTION DISPATCH
# ============================================================

def run_function_tool(
    tool_name,
    arguments,
    sf,
    salesforce_username,
    runtime_context=None,
):
    try:
        if tool_name == "search_opportunities":
            return tool_search_opportunities(
                sf,
                salesforce_username,
                arguments,
            )

        if tool_name == "search_contacts":
            return tool_search_contacts(
                sf,
                salesforce_username,
                arguments,
            )

        if tool_name == "search_accounts":
            return tool_search_accounts(
                sf,
                salesforce_username,
                arguments,
            )

        if tool_name == "find_nearby_accounts":
            return tool_find_nearby_accounts(
                sf,
                salesforce_username,
                arguments,
                (runtime_context or {}).get("location_context"),
            )

        if tool_name == "search_events":
            return tool_search_events(
                sf,
                salesforce_username,
                arguments,
            )

        if tool_name == "search_tasks":
            return tool_search_tasks(
                sf,
                salesforce_username,
                arguments,
            )

        if tool_name == "get_opportunity_context":
            return tool_get_opportunity_context(
                sf,
                salesforce_username,
                arguments,
            )

        if tool_name == "propose_update_opportunity":
            return tool_propose_update_opportunity(
                sf,
                salesforce_username,
                arguments,
            )

        if tool_name == "propose_create_event":
            return tool_propose_create_event(
                sf,
                salesforce_username,
                arguments,
            )

        if tool_name == "propose_update_event":
            return tool_propose_update_event(
                sf,
                salesforce_username,
                arguments,
            )

        return {
            "ok": False,
            "error": f"Unknown function tool: {tool_name}",
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
        }


# ============================================================
# CAPABILITY MANIFEST
# ============================================================

BASE_CAPABILITY_MANIFEST = {
    "salesforce": {
        "search_opportunities": True,
        "aggregate_opportunities": True,
        "opportunity_context": True,
        "search_accounts": True,
        "search_contacts": True,
        "update_opportunities": True,
        "search_events": True,
        "search_tasks": True,
        "create_events": True,
        "update_events": True,
        "create_tasks": False,
        "send_email": False,
    },
    "web_research": True,
    "location": {
        "foreground_gps": True,
        "demo_geography_adapter": True,
        "nearby_accounts": True,
    },
    "sessions": {
        "iphone_recording": True,
        "background_recording": True,
        "diarized_transcription": True,
        "opportunity_linking": True,
        "soft_delete": True,
        "voicepuck": "prototype_not_connected",
    },
    "voice": {
        "ask_sally": True,
    },
    "research": {
        "long_research": True,
    },
    "mobile_actions": {
        "call_contact": True,
    },
    "admin": {
        "workflows": True,
        "jargon": True,
        "knowledge": True,
        "operations": True,
    },
}


def current_capabilities():
    capabilities = json.loads(json.dumps(BASE_CAPABILITY_MANIFEST))
    flags = get_feature_flags()
    read_on = flags.get("salesforce_reads", True)
    write_on = flags.get("salesforce_writes", True)
    capabilities["salesforce"]["search_opportunities"] = read_on
    capabilities["salesforce"]["aggregate_opportunities"] = read_on
    capabilities["salesforce"]["opportunity_context"] = read_on
    capabilities["salesforce"]["search_accounts"] = read_on
    capabilities["salesforce"]["search_contacts"] = read_on
    capabilities["salesforce"]["search_events"] = read_on
    capabilities["salesforce"]["search_tasks"] = read_on
    capabilities["salesforce"]["update_opportunities"] = write_on
    capabilities["salesforce"]["create_events"] = write_on
    capabilities["salesforce"]["update_events"] = write_on
    capabilities["web_research"] = flags.get("web_research", True)
    capabilities["location"]["foreground_gps"] = flags.get("location", True)
    capabilities["location"]["demo_geography_adapter"] = flags.get("demo_geography", DEMO_GEO_ENABLED)
    capabilities["sessions"]["iphone_recording"] = flags.get("session_recording", True)
    capabilities["sessions"]["soft_delete"] = flags.get("session_soft_delete", True)
    capabilities["voice"]["ask_sally"] = flags.get("voice_chat", True)
    capabilities["research"]["long_research"] = flags.get("long_research", True)
    return capabilities



def capability_prompt():
    return (
        "Available CMD Sally capabilities (authoritative):\n"
        + json.dumps(current_capabilities(), indent=2)
        + "\nNever claim an unavailable capability exists."
    )


# ============================================================
# ROUTER
# ============================================================

class RouteDecision(BaseModel):
    action: Literal["answer", "reroute"]

    route: Literal[
        "simple",
        "crm_read",
        "crm_analysis",
        "web_simple",
        "web_research",
        "workflow",
        "deep_complex",
    ]

    target_model: Literal[
        "gpt-5.6-luna",
        "gpt-5.6-terra",
        "gpt-5.6-sol",
    ]

    reasoning_effort: Literal[
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
    ]

    needs_salesforce: bool
    needs_web: bool
    needs_write: bool
    requires_confirmation: bool
    routing_note: str
    answer: Optional[str]


# ============================================================
# CONVERSATION CONTEXT
# ============================================================

# The mobile app sends a small rolling window of the visible conversation with
# each request. The backend remains stateless for the pilot, but Sally can still
# understand references such as "that one", "the earlier customer", etc.
MAX_HISTORY_MESSAGES = 20
MAX_HISTORY_CHARS_PER_MESSAGE = 4000
MAX_HISTORY_TOTAL_CHARS = 24000


def normalize_conversation_history(raw_history):
    if not isinstance(raw_history, list):
        return []

    cleaned = []

    for item in raw_history:
        if not isinstance(item, dict):
            continue

        role = item.get("role")
        if role not in {"user", "assistant"}:
            continue

        content = item.get("content")
        if content is None:
            content = item.get("text")

        if not isinstance(content, str):
            continue

        content = content.strip()
        if not content:
            continue

        cleaned.append({
            "role": role,
            "content": content[:MAX_HISTORY_CHARS_PER_MESSAGE],
        })

    # Keep the newest messages, while also enforcing a total character budget.
    selected_reversed = []
    total_chars = 0

    for item in reversed(cleaned):
        if len(selected_reversed) >= MAX_HISTORY_MESSAGES:
            break

        remaining = MAX_HISTORY_TOTAL_CHARS - total_chars
        if remaining <= 0:
            break

        content = item["content"][:remaining]
        if not content:
            break

        selected_reversed.append({
            "role": item["role"],
            "content": content,
        })
        total_chars += len(content)

    return list(reversed(selected_reversed))


def normalize_client_context(raw_context):
    if not isinstance(raw_context, dict):
        return {}

    context = {}

    timezone = raw_context.get("timezone")
    if isinstance(timezone, str) and timezone.strip():
        context["timezone"] = timezone.strip()[:100]

    local_datetime = raw_context.get("local_datetime")
    if isinstance(local_datetime, str) and local_datetime.strip():
        context["local_datetime"] = local_datetime.strip()[:80]

    utc_offset_minutes = raw_context.get("utc_offset_minutes")
    if isinstance(utc_offset_minutes, (int, float)):
        context["utc_offset_minutes"] = int(utc_offset_minutes)

    geo_session_id = raw_context.get("geo_session_id")
    if isinstance(geo_session_id, str) and geo_session_id.strip():
        context["geo_session_id"] = geo_session_id.strip()[:100]

    raw_location = raw_context.get("location")
    if isinstance(raw_location, dict):
        try:
            lat = float(raw_location.get("latitude"))
            lon = float(raw_location.get("longitude"))
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                context["location"] = {
                    "latitude": lat,
                    "longitude": lon,
                    "accuracy_m": raw_location.get("accuracy_m"),
                    "city": str(raw_location.get("city") or "")[:120] or None,
                    "region": str(raw_location.get("region") or "")[:120] or None,
                    "country": str(raw_location.get("country") or "")[:120] or None,
                    "iso_country_code": str(raw_location.get("iso_country_code") or "")[:12] or None,
                    "captured_at": str(raw_location.get("captured_at") or "")[:80] or None,
                }
        except Exception:
            pass

    return context


def client_time_prompt(client_context):
    parts = ["Server date: " + date.today().isoformat()]

    if client_context.get("local_datetime"):
        parts.append(
            "User device local date/time: "
            + client_context["local_datetime"]
        )

    if client_context.get("timezone"):
        parts.append("User timezone: " + client_context["timezone"])

    if "utc_offset_minutes" in client_context:
        parts.append(
            "User UTC offset in minutes: "
            + str(client_context["utc_offset_minutes"])
        )

    if client_context.get("location"):
        loc = client_context["location"]
        parts.append(
            "User device supplied a current foreground location: "
            + (location_label(loc) or f"{loc.get('latitude')}, {loc.get('longitude')}")
        )

    return "\n".join(parts)


def conversation_items(history, latest_user_message):
    items = [
        {
            "role": item["role"],
            "content": item["content"],
        }
        for item in history
    ]

    items.append({
        "role": "user",
        "content": latest_user_message,
    })

    return items


ROUTER_INSTRUCTIONS = """
You are the intelligent routing layer for an enterprise sales CRM AI assistant.

You receive the recent conversation followed by the user's latest request.
Treat the latest request as a continuation of that conversation. Resolve normal
references such as "that one", "the earlier one", "this customer", "it",
"the first deal", and similar phrases from the supplied history whenever the
referent is clear. Do not ask the user to repeat information that is already
unambiguous in the recent conversation.

Either answer it directly when it is genuinely simple, or route it to an
execution tier.

ROUTES

SIMPLE
- General knowledge only.
- No Salesforce.
- No web/current information.
- No workflow.
Use Luna low and answer directly.

CRM_READ
- Salesforce retrieval/filtering/counting/aggregation/straightforward summarization.
- Opportunities, accounts, customers, addresses, contacts, contact roles, Salesforce Events/meetings, and Tasks.
- Questions such as biggest/top deals, closing this week/month/quarter, overdue opportunities, pipeline totals, grouped pipeline, meetings in a period, and overdue Tasks should normally remain CRM_READ because Salesforce performs the filtering/aggregation directly.
- Nearby customer/account questions that depend on the user's current location.
Use Luna low. needs_salesforce=true.

CRM_ANALYSIS
- Salesforce data plus comparison, prioritization, risk assessment,
  recommendations, or strategic interpretation.
Use Terra medium/high. needs_salesforce=true.

WEB_SIMPLE
- Current public information is required and the task is straightforward.
Use Terra medium. needs_web=true.

WEB_RESEARCH
- Multiple searches/sources/comparisons, competitive intelligence, or
  CRM + current web synthesis.
Use Terra high. needs_web=true.
Set needs_salesforce=true when CRM data is also required.

WORKFLOW
- Several dependent actions, or any request to change Salesforce.
- Research + analysis + action also belongs here.
Use Terra high.
Set needs_salesforce=true for Salesforce work.
Set needs_web=true when current public research is requested.
Set needs_write=true for Salesforce changes.
All Salesforce writes require explicit confirmation:
requires_confirmation=true.

DEEP_COMPLEX
- Very broad, difficult, high-value, multi-source strategic reasoning.
Use Sol high/xhigh/max.
Set needs_salesforce and needs_web as required.
If the user also asks for writes, needs_write=true and
requires_confirmation=true.

RULES

Never fabricate Salesforce data.
Never answer Salesforce-specific questions without Salesforce data.
If the latest message refers to a Salesforce account, opportunity, contact,
customer, deal, Event/meeting, or prior CRM result from the conversation, normally route with
needs_salesforce=true so the current CRM state can be verified.
Conversation history is context, not proof that a CRM fact is still current.
Never pretend web research occurred.
If current information is required, needs_web=true.
If Salesforce data is required, needs_salesforce=true.
If Salesforce changes are requested, needs_write=true.
Nearby/"near me"/field-visit requests require Salesforce and the location-aware nearby tool.
Every Salesforce write requires explicit confirmation.
Do not unnecessarily escalate simple work.
routing_note must be a short explanation, not chain-of-thought.
When action=reroute, answer must be null.
When action=answer, answer contains the final user-facing answer.
"""


def route_or_answer(
    user_message,
    history=None,
    client_context=None,
    location_context=None,
):
    history = history or []
    client_context = client_context or {}

    response = openai_client.responses.parse(
        model="gpt-5.6-luna",
        reasoning={"effort": "low"},
        store=False,
        input=[
            {
                "role": "developer",
                "content": (
                    ROUTER_INSTRUCTIONS
                    + "\n\n"
                    + client_time_prompt(client_context)
                    + "\n\n"
                    + configurable_context_prompt()
                ),
            },
            *conversation_items(history, user_message),
        ],
        text_format=RouteDecision,
    )

    decision = response.output_parsed

    if decision is None:
        raise Exception(
            "OpenAI router returned no structured decision."
        )

    return decision


# ============================================================
# AGENT CONFIG
# ============================================================

AGENT_INSTRUCTIONS = """
You are CMD Sally, an enterprise sales CRM and research assistant.

Conversation:
- Treat the latest user message as a continuation of the recent conversation.
- Resolve pronouns and references from history when the referent is clear.
- Do not make the user repeat a customer, opportunity, contact, Event, date, or
  choice that is already clear from the conversation.
- If a follow-up depends on CRM state, re-query Salesforce as needed rather than
  assuming an old value is still current.
- If more than one plausible referent remains, ask one concise clarification.
- The capability manifest and actual tools supplied to this request are
  authoritative. Never claim a capability exists merely because an earlier
  assistant message claimed it.

Salesforce:
- The user is authenticated through Microsoft Entra.
- The backend authenticates to Salesforce as the corresponding Salesforce user.
- Use Salesforce tools whenever the request depends on CRM data.
- Prefer Salesforce-native filtering, sorting, relative-date literals and aggregation through search_opportunities/search_events/search_tasks rather than fetching broad datasets and manually filtering them in the model.
- For a known deal that needs history, contacts, Events or Tasks, use get_opportunity_context.
- Never invent CRM records or fields.
- Account billing/shipping addresses are customer/site address information.
- Contact mailing addresses are contact-level addresses.
- Opportunity contacts are represented by Opportunity Contact Roles.
- If the user asks to call a contact, resolve the correct Contact/primary Opportunity Contact Role so the mobile UI can show a callable phone action. Do not claim a phone call was placed; the user must tap the native Call action.
- Salesforce Events represent meetings/appointments. WhoId is the person side
  (Contact in this pilot); WhatId is the related Account or Opportunity.
- Resolve relative meeting dates/times from the supplied user device local time
  and timezone. Event date-times sent to tools must include an explicit offset.
- Distinguish Salesforce facts from your interpretation.

Location:
- When the backend supplies a location context, use its effective CRM location for nearby workflows.
- The backend, not the model, calculates geographic distance. Use find_nearby_accounts.
- If location mode is demo, clearly label recommendations as using a demo-translated location.
- Never pretend the user is physically located at the demo location.

Web:
- If this request was routed as needing web research, you MUST use web_search
  before giving the final answer.
- Prefer current, authoritative, first-party sources when available.
- Do not claim a current public fact without web support.
- Keep source attribution clear.

Writes:
- Write-capable tools only PROPOSE changes; they never write immediately.
- Supported write proposals are Opportunity updates, Event creation, and Event updates.
- Never say Salesforce was updated/created until the backend confirmation endpoint
  reports success.
- If changes are pending, summarize exactly what would change and tell the user
  explicit confirmation is required.

Presentation:
- The mobile UI renders structured CRM results separately from your prose.
- Do NOT dump Salesforce rows into a long prose list or Markdown table.
- display_text should explain the result, highlight conclusions, and stay concise.
- speech_text is private text for device TTS and is NOT displayed. It must sound
  natural when spoken. Do not read tables, URLs, Salesforce IDs, citations, or
  long lists unless the user explicitly asked you to read them. Prefer totals,
  priorities, and the most important 1-3 items, then say that details are on screen.
- When the user explicitly asks to hear/read the detailed list, speech_text may
  contain more detail.
- Your FINAL response must be ONLY a valid JSON object, with no Markdown fences:
  {"display_text":"...","speech_text":"..."}

You may call multiple tools and combine Salesforce data with web research.
"""


def model_and_effort_for_route(decision):
    if decision.route == "crm_read":
        return "gpt-5.6-luna", "low"

    if decision.route == "crm_analysis":
        effort = (
            decision.reasoning_effort
            if decision.reasoning_effort in {"medium", "high", "xhigh", "max"}
            else "medium"
        )
        return "gpt-5.6-terra", effort

    if decision.route == "web_simple":
        return "gpt-5.6-terra", "medium"

    if decision.route in {"web_research", "workflow"}:
        return "gpt-5.6-terra", "high"

    if decision.route == "deep_complex":
        effort = (
            decision.reasoning_effort
            if decision.reasoning_effort in {"high", "xhigh", "max"}
            else "high"
        )
        return "gpt-5.6-sol", effort

    raise Exception(f"Execution not enabled for route: {decision.route}")


def build_tools_for_decision(decision):
    tools = []

    if decision.needs_salesforce:
        tools.extend(CRM_READ_TOOLS)

    if decision.needs_write:
        tools.extend(CRM_WRITE_TOOLS)

    if decision.needs_web:
        tools.append({"type": "web_search"})

    return tools


def collect_web_metadata(response):
    dumped = response.model_dump()

    used = False
    searches = []
    sources_by_url = {}

    for item in dumped.get("output", []):
        item_type = item.get("type")

        if item_type == "web_search_call":
            used = True
            action = item.get("action") or {}

            searches.append({
                "type": action.get("type"),
                "query": action.get("query"),
                "queries": action.get("queries"),
            })

            for source in action.get("sources") or []:
                url = source.get("url")
                if url:
                    sources_by_url[url] = {
                        "title": source.get("title"),
                        "url": url,
                    }

        if item_type == "message":
            for content in item.get("content") or []:
                for annotation in content.get("annotations") or []:
                    if annotation.get("type") == "url_citation":
                        url = annotation.get("url")
                        if url:
                            sources_by_url[url] = {
                                "title": annotation.get("title"),
                                "url": url,
                            }

    return {
        "used": used,
        "searches": searches,
        "sources": list(sources_by_url.values()),
    }


def dedupe_pending_actions(actions):
    unique = []
    seen = set()

    for action in actions:
        action_type = action.get("action")

        if action_type == "update_opportunity":
            key = (
                action_type,
                action.get("opportunity_id"),
                action.get("field_name"),
                json.dumps(action.get("new_value"), sort_keys=True),
            )
        elif action_type == "update_event":
            key = (
                action_type,
                action.get("event_id"),
                action.get("field_name"),
                json.dumps(action.get("new_value"), sort_keys=True),
            )
        elif action_type == "create_event":
            key = (
                action_type,
                json.dumps(action.get("fields") or {}, sort_keys=True),
            )
        else:
            key = (action_type, json.dumps(action, sort_keys=True, default=str))

        if key not in seen:
            seen.add(key)
            unique.append(action)

    return unique


def parse_agent_presentation(raw_text):
    raw = (raw_text or "").strip()
    if not raw:
        raise ValueError("Agent returned an empty final response.")

    candidate = raw
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\\s*", "", candidate, flags=re.I)
        candidate = re.sub(r"\\s*```$", "", candidate)

    try:
        data = json.loads(candidate)
    except Exception:
        # Backward-compatible safety fallback: show the text and speak a shortened
        # version. This prevents a malformed presentation wrapper from breaking chat.
        clean = raw[:6000]
        speech = clean
        if len(speech) > 650:
            speech = speech[:600].rsplit(" ", 1)[0] + ". I've put the details on screen."
        return {
            "display_text": clean,
            "speech_text": speech,
        }

    display_text = str(data.get("display_text") or "").strip()
    speech_text = str(data.get("speech_text") or "").strip()

    if not display_text:
        display_text = "I've put the result on screen."
    if not speech_text:
        speech_text = display_text

    return {
        "display_text": display_text[:8000],
        "speech_text": speech_text[:2400],
    }


def ui_block_from_tool_result(tool_name, result, call_id):
    if not result or not result.get("ok"):
        return None

    if tool_name == "search_opportunities":
        if result.get("summary_rows") is not None:
            return {
                "type": "opportunity_summary",
                "title": "Opportunity summary",
                "count": result.get("count", 0),
                "items": result.get("summary_rows") or [],
                "aggregate": result.get("aggregate"),
                "group_by": result.get("group_by"),
                "source_tool_call": call_id,
            }
        return {
            "type": "opportunity_list",
            "title": "Opportunities",
            "count": result.get("count", 0),
            "items": result.get("opportunities") or [],
            "source_tool_call": call_id,
        }

    if tool_name == "find_nearby_accounts":
        return {
            "type": "nearby_account_list",
            "title": "Nearby customers",
            "count": result.get("count", 0),
            "items": result.get("nearby_accounts") or [],
            "location_context": result.get("location_context"),
            "source_tool_call": call_id,
        }

    if tool_name == "search_events":
        return {
            "type": "event_list",
            "title": "Salesforce Events",
            "count": result.get("count", 0),
            "items": result.get("events") or [],
            "source_tool_call": call_id,
        }

    if tool_name == "search_accounts":
        return {
            "type": "account_list",
            "title": "Accounts",
            "count": result.get("count", 0),
            "items": result.get("accounts") or [],
            "source_tool_call": call_id,
        }

    if tool_name == "search_contacts":
        return {
            "type": "contact_list",
            "title": "Contacts",
            "count": result.get("count", 0),
            "items": result.get("contacts") or [],
            "source_tool_call": call_id,
        }

    if tool_name == "search_tasks":
        return {
            "type": "task_list",
            "title": "Salesforce Tasks",
            "count": result.get("count", 0),
            "items": result.get("tasks") or [],
            "source_tool_call": call_id,
        }

    if tool_name == "get_opportunity_context":
        return {
            "type": "opportunity_context",
            "title": "Opportunity context",
            "count": 1,
            "items": [{
                "opportunity": result.get("opportunity"),
                "events": result.get("events") or [],
                "tasks": result.get("tasks") or [],
            }],
            "source_tool_call": call_id,
        }

    return None


def build_conversation_text(display_text, ui_blocks, pending_actions):
    parts = [display_text]

    for block in ui_blocks or []:
        block_type = block.get("type")
        items = block.get("items") or []

        if block_type == "opportunity_list":
            rows = []
            for index, item in enumerate(items[:15], start=1):
                rows.append(
                    f"{index}. Opportunity: {item.get('name')} | Account: "
                    f"{(item.get('account') or {}).get('name')} | Stage: {item.get('stage')} | "
                    f"Amount: {item.get('amount')} | Close: {item.get('close_date')}"
                )
            if rows:
                parts.append("Structured opportunities shown on screen:\n" + "\n".join(rows))

        elif block_type == "nearby_account_list":
            rows = []
            for index, item in enumerate(items[:10], start=1):
                rows.append(
                    f"{index}. Nearby Account: {(item.get('account') or {}).get('name')} | "
                    f"Distance km: {item.get('distance_km')} | Open pipeline: {item.get('open_pipeline')} | "
                    f"Top opportunity: {(item.get('top_opportunity') or {}).get('name')}"
                )
            if rows:
                parts.append("Structured nearby Accounts shown on screen:\n" + "\n".join(rows))

        elif block_type == "event_list":
            rows = []
            for index, item in enumerate(items[:15], start=1):
                rows.append(
                    f"{index}. Event: {item.get('subject')} | Start: {item.get('start_datetime')} | "
                    f"End: {item.get('end_datetime')} | Who: {(item.get('who') or {}).get('name')} | "
                    f"What: {(item.get('what') or {}).get('name')}"
                )
            if rows:
                parts.append("Structured Events shown on screen:\n" + "\n".join(rows))

        elif block_type == "account_list":
            rows = [
                f"{i}. Account: {item.get('name')} | Industry: {item.get('industry')}"
                for i, item in enumerate(items[:15], start=1)
            ]
            if rows:
                parts.append("Structured Accounts shown on screen:\n" + "\n".join(rows))

        elif block_type == "contact_list":
            rows = [
                f"{i}. Contact: {item.get('name')} | Title: {item.get('title')} | "
                f"Account: {(item.get('account') or {}).get('name')}"
                for i, item in enumerate(items[:15], start=1)
            ]
            if rows:
                parts.append("Structured Contacts shown on screen:\n" + "\n".join(rows))

        elif block_type == "task_list":
            rows = [
                f"{i}. Task: {item.get('subject')} | Due: {item.get('activity_date')} | Status: {item.get('status')} | "
                f"What: {(item.get('what') or {}).get('name')}"
                for i, item in enumerate(items[:15], start=1)
            ]
            if rows:
                parts.append("Structured Tasks shown on screen:\n" + "\n".join(rows))

        elif block_type == "opportunity_summary":
            rows = [f"{i}. Group: {item.get('group')} | {item.get('aggregate')}: {item.get('value')}" for i,item in enumerate(items[:20],start=1)]
            if rows:
                parts.append("Structured Opportunity aggregate shown on screen:\n" + "\n".join(rows))

        elif block_type == "opportunity_context":
            if items:
                opp = (items[0] or {}).get("opportunity") or {}
                parts.append(
                    "Opportunity context shown on screen: "
                    f"{opp.get('name')} | Stage {opp.get('stage')} | Amount {opp.get('amount')} | "
                    f"Confidence {opp.get('confidence_level')} | Forecast {opp.get('add_to_forecast')} | "
                    f"Primary product {opp.get('primary_product')} | Primary contact {(opp.get('primary_contact') or {}).get('name')}"
                )

    if pending_actions:
        parts.append(
            "Pending Salesforce actions shown for confirmation: "
            + json.dumps(pending_actions, default=str)[:5000]
        )

    return "\n\n".join(parts)[:12000]



def create_confirmation_token(claims, salesforce_username, actions):
    now = int(time.time())

    payload = {
        "iss": "cmd-ai-api",
        "aud": "cmd-ai-write-confirmation",
        "type": "salesforce_write_confirmation",
        "oid": claims.get("oid"),
        "tid": claims.get("tid"),
        "salesforce_username": salesforce_username,
        "actions": actions,
        "iat": now,
        "exp": now + 600,
    }

    return jwt.encode(
        payload,
        APP_SIGNING_SECRET,
        algorithm="HS256",
    )


def emit_progress(callback, code, message, detail=None):
    if callback:
        try:
            callback(code, message, detail or {})
        except Exception:
            pass


def tool_progress_message(tool_name, arguments):
    arguments = arguments or {}
    if tool_name == "search_opportunities":
        if arguments.get("overdue"):
            return "Checking Salesforce for overdue opportunities…"
        if arguments.get("close_date_relative"):
            label = str(arguments.get("close_date_relative")).replace("_", " ").lower()
            return f"Finding opportunities for {label}…"
        if arguments.get("aggregate") and arguments.get("aggregate") != "none":
            return "Calculating Salesforce pipeline summary…"
        return "Querying Salesforce opportunities…"
    if tool_name == "get_opportunity_context": return "Loading opportunity history, contacts and activities…"
    if tool_name == "search_events": return "Checking Salesforce meetings and events…"
    if tool_name == "search_tasks":
        return "Checking overdue Salesforce tasks…" if arguments.get("overdue") else "Checking Salesforce tasks…"
    if tool_name == "search_contacts": return "Looking up Salesforce contacts…"
    if tool_name == "search_accounts": return "Looking up Salesforce accounts…"
    if tool_name == "find_nearby_accounts": return "Finding nearby customers in Salesforce…"
    if tool_name.startswith("propose_"): return "Preparing a Salesforce change for your review…"
    return "Working with Salesforce…"


def execute_agent(
    user_message,
    decision,
    sf,
    salesforce_username,
    claims,
    history=None,
    client_context=None,
    location_context=None,
    progress_callback=None,
    request_id=None,
):
    history = history or []
    client_context = client_context or {}

    model, effort = model_and_effort_for_route(decision)
    tools = build_tools_for_decision(decision)

    input_items = [
        {
            "role": "developer",
            "content": (
                AGENT_INSTRUCTIONS
                + "\n\n"
                + capability_prompt()
                + "\n\n"
                + client_time_prompt(client_context)
                + "\n\n"
                + location_prompt(location_context)
                + "\n\n"
                + configurable_context_prompt()
                + "\n\nRoute selected: "
                + decision.route
                + "\nWeb required: "
                + str(decision.needs_web)
                + "\nSalesforce required: "
                + str(decision.needs_salesforce)
                + "\nWrite requested: "
                + str(decision.needs_write)
            ),
        },
        *conversation_items(history, user_message),
    ]

    tool_trace = []
    pending_actions = []
    ui_blocks = []
    all_web_sources = {}
    web_search_trace = []
    web_used = False
    force_web_next_round = False

    for round_number in range(1, 10):
        current_tools = tools
        tool_choice = "auto"
        forcing_web = force_web_next_round

        if force_web_next_round:
            current_tools = [{"type": "web_search"}]
            tool_choice = "required"
            force_web_next_round = False
        elif round_number == 1 and decision.needs_web:
            # Guarantees at least some tool work begins immediately.
            # For web-only routes, the only available tool is web_search.
            tool_choice = "required"

        kwargs = {
            "model": model,
            "reasoning": {"effort": effort},
            "tools": current_tools,
            "tool_choice": tool_choice,
            "input": input_items,
            "store": False,
        }

        if decision.needs_web:
            kwargs["include"] = ["web_search_call.action.sources"]

        if forcing_web or (decision.needs_web and not web_used and round_number > 1):
            emit_progress(progress_callback, "web_search", "Searching the web…")
        elif round_number == 1 and decision.needs_web and decision.needs_salesforce:
            emit_progress(progress_callback, "agent_plan", "Planning Salesforce and web research…")
        elif round_number == 1 and decision.needs_web:
            emit_progress(progress_callback, "web_search", "Searching the web…")
        elif round_number == 1 and decision.needs_salesforce:
            emit_progress(progress_callback, "agent_plan", "Planning the Salesforce lookup…")
        elif round_number > 1:
            emit_progress(progress_callback, "synthesizing", "Analyzing the results…")

        response = openai_client.responses.create(**kwargs)

        web_meta = collect_web_metadata(response)

        if web_meta["used"]:
            web_used = True
            emit_progress(progress_callback, "web_review", "Reviewing web research…")
            audit_log("web_search", owner_oid=claims.get("oid"), salesforce_username=salesforce_username,
                      request_id=request_id, summary="Web research performed",
                      details={"search_count": len(web_meta.get("searches") or []), "source_count": len(web_meta.get("sources") or [])})

        web_search_trace.extend(web_meta["searches"])

        for source in web_meta["sources"]:
            if source.get("url"):
                all_web_sources[source["url"]] = source

        input_items += response.output

        function_calls = [
            item
            for item in response.output
            if item.type == "function_call"
        ]

        if not function_calls:
            if decision.needs_web and not web_used:
                input_items.append({
                    "role": "developer",
                    "content": (
                        "The request requires current web research, but no web "
                        "search has been performed yet. Perform web_search now "
                        "before producing the final answer."
                    ),
                })
                force_web_next_round = True
                continue

            emit_progress(progress_callback, "finalizing", "Preparing Sally's answer…")
            raw_answer = (response.output_text or "").strip()

            if not raw_answer:
                raise Exception(
                    "Agent completed without a final text answer."
                )

            presentation = parse_agent_presentation(raw_answer)
            pending_actions = dedupe_pending_actions(pending_actions)

            confirmation_token = None

            if pending_actions:
                confirmation_token = create_confirmation_token(
                    claims,
                    salesforce_username,
                    pending_actions,
                )

            conversation_text = build_conversation_text(
                presentation["display_text"],
                ui_blocks,
                pending_actions,
            )

            return {
                "answer": presentation["display_text"],
                "display_text": presentation["display_text"],
                "speech_text": presentation["speech_text"],
                "conversation_text": conversation_text,
                "ui_blocks": ui_blocks,
                "execution_model": model,
                "reasoning_effort": effort,
                "tool_rounds": round_number - 1,
                "tool_trace": tool_trace,
                "web_used": web_used,
                "web_search_trace": web_search_trace,
                "web_sources": list(all_web_sources.values()),
                "pending_actions": pending_actions,
                "confirmation_required": bool(pending_actions),
                "confirmation_token": confirmation_token,
                "location_context": location_context,
            }

        for call in function_calls:
            try:
                arguments = json.loads(call.arguments)
            except Exception as e:
                arguments = None
                result = {
                    "ok": False,
                    "error": f"Invalid tool arguments: {e}",
                }
            else:
                if sf is None:
                    result = {
                        "ok": False,
                        "error": (
                            "Salesforce tool requested, but Salesforce "
                            "was not enabled for this route."
                        ),
                    }
                else:
                    emit_progress(progress_callback, "salesforce_tool", tool_progress_message(call.name, arguments), {"tool": call.name})
                    result = run_function_tool(
                        call.name,
                        arguments,
                        sf,
                        salesforce_username,
                        runtime_context={"location_context": location_context, "request_id": request_id},
                    )

            if result.get("pending_action"):
                pending_actions.append(result["pending_action"])

            ui_block = ui_block_from_tool_result(call.name, result, call.call_id)
            if ui_block:
                ui_blocks.append(ui_block)

            tool_trace.append({
                "round": round_number,
                "tool": call.name,
                "arguments": arguments,
                "ok": result.get("ok", False),
                "result_count": result.get("count"),
                "status": result.get("status"),
            })
            audit_log(
                "salesforce_tool" if call.name != "web_search" else "web_tool",
                owner_oid=claims.get("oid"), salesforce_username=salesforce_username, request_id=request_id,
                summary=f"{call.name}: {'ok' if result.get('ok') else 'failed'}",
                details={"tool": call.name, "ok": result.get("ok", False), "count": result.get("count"), "status": result.get("status")},
            )

            input_items.append({
                "type": "function_call_output",
                "call_id": call.call_id,
                "output": json.dumps(result, default=str),
            })

    raise Exception(
        "Agent exceeded the maximum number of tool rounds."
    )


# ============================================================
# WRITE CONFIRMATION
# ============================================================

def decode_confirmation_token(token):
    return jwt.decode(
        token,
        APP_SIGNING_SECRET,
        algorithms=["HS256"],
        audience="cmd-ai-write-confirmation",
        issuer="cmd-ai-api",
    )


def execute_confirmed_actions(claims, token_payload):
    if token_payload.get("type") != "salesforce_write_confirmation":
        raise ValueError("Invalid confirmation token type.")

    if token_payload.get("oid") != claims.get("oid"):
        raise ValueError("Confirmation token belongs to a different Entra user.")

    if token_payload.get("tid") != claims.get("tid"):
        raise ValueError("Confirmation token belongs to a different Entra tenant.")

    salesforce_username = claims.get("preferred_username")

    if (
        not salesforce_username
        or token_payload.get("salesforce_username") != salesforce_username
    ):
        raise ValueError("Confirmation token Salesforce identity does not match.")

    actions = token_payload.get("actions") or []
    if not actions:
        raise ValueError("No actions were found in the confirmation token.")

    sf = get_salesforce_access_token(salesforce_username)
    validated = []

    # Prevalidate every action before executing anything.
    for action in actions:
        action_type = action.get("action")

        if action_type == "update_opportunity":
            field_name = action.get("field_name")
            opportunity_id = action.get("opportunity_id")
            new_value = normalize_opportunity_write_value(
                field_name, action.get("new_value")
            )
            current = get_owned_opportunity_field(
                sf, salesforce_username, opportunity_id, field_name
            )

            if not values_equivalent(current["current_value"], action.get("old_value")):
                raise ValueError(
                    f"Conflict: {current['name']} → {field_name} changed after the "
                    "proposal was created. No writes were executed."
                )

            validated.append({
                "action": action_type,
                "opportunity_id": current["id"],
                "opportunity_name": current["name"],
                "field_name": field_name,
                "old_value": current["current_value"],
                "new_value": new_value,
            })
            continue

        if action_type == "create_event":
            raw_fields = action.get("fields") or {}
            fields = {}
            for field_name, value in raw_fields.items():
                fields[field_name] = normalize_event_write_value(field_name, value)

            validate_event_temporal_fields(fields)

            if fields.get("WhoId"):
                get_scoped_related_record(
                    sf, salesforce_username, fields["WhoId"], "who"
                )
            if fields.get("WhatId"):
                get_scoped_related_record(
                    sf, salesforce_username, fields["WhatId"], "what"
                )

            validated.append({
                "action": action_type,
                "fields": fields,
                "event_subject": fields.get("Subject"),
            })
            continue

        if action_type == "update_event":
            event_id = action.get("event_id")
            field_name = action.get("field_name")
            new_value = normalize_event_write_value(
                field_name, action.get("new_value")
            )
            current = get_owned_event_field(
                sf, salesforce_username, event_id, field_name
            )

            if not values_equivalent(current["current_value"], action.get("old_value")):
                raise ValueError(
                    f"Conflict: Event '{current['subject']}' → {field_name} changed "
                    "after the proposal was created. No writes were executed."
                )

            if field_name == "WhoId" and new_value:
                get_scoped_related_record(sf, salesforce_username, new_value, "who")
            elif field_name == "WhatId" and new_value:
                get_scoped_related_record(sf, salesforce_username, new_value, "what")

            validated.append({
                "action": action_type,
                "event_id": current["id"],
                "event_subject": current["subject"],
                "field_name": field_name,
                "old_value": current["current_value"],
                "new_value": new_value,
            })
            continue

        raise ValueError(f"Unsupported confirmed action: {action_type}")

    results = []

    for action in validated:
        action_type = action["action"]

        if action_type == "update_opportunity":
            salesforce_update_opportunity(
                sf["access_token"],
                sf["instance_url"],
                action["opportunity_id"],
                {action["field_name"]: action["new_value"]},
            )

            verified = get_owned_opportunity_field(
                sf,
                salesforce_username,
                action["opportunity_id"],
                action["field_name"],
            )

            if not values_equivalent(verified["current_value"], action["new_value"]):
                raise ValueError("Salesforce Opportunity write could not be verified.")

            results.append({
                **action,
                "status": "updated_and_verified",
                "verified_value": verified["current_value"],
            })
            continue

        if action_type == "create_event":
            event_id = salesforce_create_record(
                sf["access_token"],
                sf["instance_url"],
                "Event",
                action["fields"],
            )

            event = get_owned_event(sf, salesforce_username, event_id)

            for field_name, expected in action["fields"].items():
                actual_key = {
                    "Subject": "subject",
                    "StartDateTime": "start_datetime",
                    "EndDateTime": "end_datetime",
                    "ActivityDate": "activity_date",
                    "IsAllDayEvent": "is_all_day_event",
                    "Location": "location",
                    "Description": "description",
                    "WhoId": None,
                    "WhatId": None,
                }.get(field_name)

                if field_name == "WhoId":
                    actual = (event.get("who") or {}).get("id")
                elif field_name == "WhatId":
                    actual = (event.get("what") or {}).get("id")
                else:
                    actual = event.get(actual_key)

                if not values_equivalent(actual, expected):
                    raise ValueError(
                        f"Salesforce Event creation could not be verified for {field_name}."
                    )

            results.append({
                "action": action_type,
                "event_id": event_id,
                "event_subject": event.get("subject"),
                "status": "created_and_verified",
                "event": event,
            })
            continue

        if action_type == "update_event":
            salesforce_update_record(
                sf["access_token"],
                sf["instance_url"],
                "Event",
                action["event_id"],
                {action["field_name"]: action["new_value"]},
            )

            verified = get_owned_event_field(
                sf,
                salesforce_username,
                action["event_id"],
                action["field_name"],
            )

            if not values_equivalent(verified["current_value"], action["new_value"]):
                raise ValueError("Salesforce Event update could not be verified.")

            results.append({
                **action,
                "status": "updated_and_verified",
                "verified_value": verified["current_value"],
            })
            continue

    return results



# ============================================================
# SESSIONS — AUDIO -> DIARIZATION -> MEETING INTELLIGENCE
# ============================================================


class SessionIntelligence(BaseModel):
    title: str
    summary: str
    key_points: list[str] = Field(default_factory=list)
    customer_needs: list[str] = Field(default_factory=list)
    products_discussed: list[str] = Field(default_factory=list)
    competitors: list[str] = Field(default_factory=list)
    decisions: list[str] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    follow_ups: list[str] = Field(default_factory=list)
    rep_commitments: list[str] = Field(default_factory=list)
    customer_commitments: list[str] = Field(default_factory=list)
    people_mentioned: list[str] = Field(default_factory=list)
    linked_opportunity_id: Optional[str] = None
    link_confidence: float = 0.0
    link_reason: str = ""


def open_opportunity_candidates(sf, salesforce_username):
    result = tool_search_opportunities(
        sf,
        salesforce_username,
        {
            "name_contains": None,
            "account_name_contains": None,
            "status": "open",
            "stage": None,
            "min_amount": None,
            "max_amount": None,
            "close_date_from": None,
            "close_date_to": None,
            "account_city": None,
            "account_state": None,
            "account_country": None,
            "include_contacts": True,
            "limit": 100,
        },
    )
    candidates = []
    for opp in result.get("opportunities", []):
        candidates.append({
            "id": opp.get("id"),
            "name": opp.get("name"),
            "account": (opp.get("account") or {}).get("name"),
            "stage": opp.get("stage"),
            "amount": opp.get("amount"),
            "close_date": opp.get("close_date"),
            "next_step": opp.get("next_step"),
            "description": opp.get("description"),
            "contacts": [
                {
                    "name": (role.get("contact") or {}).get("name"),
                    "title": (role.get("contact") or {}).get("title"),
                    "role": role.get("role"),
                }
                for role in (opp.get("contacts") or [])[:8]
            ],
        })
    return candidates


def split_audio_if_needed(audio_path, processing_dir):
    source = Path(audio_path)
    if source.stat().st_size <= MAX_OPENAI_AUDIO_BYTES:
        return [(source, 0.0)]

    processing_dir = Path(processing_dir)
    processing_dir.mkdir(parents=True, exist_ok=True)
    pattern = processing_dir / "chunk_%03d.m4a"
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    command = [
        ffmpeg,
        "-hide_banner", "-loglevel", "error", "-y",
        "-i", str(source),
        "-map", "0:a:0",
        "-c:a", "aac",
        "-b:a", "48k",
        "-ac", "1",
        "-ar", "32000",
        "-f", "segment",
        "-segment_time", str(SESSION_CHUNK_SECONDS),
        "-reset_timestamps", "1",
        str(pattern),
    ]
    subprocess.run(command, check=True, timeout=20 * 60)
    chunks = sorted(processing_dir.glob("chunk_*.m4a"))
    if not chunks:
        raise RuntimeError("Audio exceeded 25 MB and could not be split for transcription.")
    for chunk in chunks:
        if chunk.stat().st_size > MAX_OPENAI_AUDIO_BYTES:
            raise RuntimeError("A generated transcription chunk still exceeds the OpenAI upload limit.")
    return [(chunk, index * float(SESSION_CHUNK_SECONDS)) for index, chunk in enumerate(chunks)]


def diarize_audio_files(audio_parts):
    combined_segments = []
    combined_text = []
    duration = 0.0

    for chunk_index, (path, offset) in enumerate(audio_parts):
        with open(path, "rb") as audio_file:
            audio_client = OpenAI(api_key=OPENAI_API_KEY, timeout=30 * 60)
            transcript = audio_client.audio.transcriptions.create(
                model="gpt-4o-transcribe-diarize",
                file=audio_file,
                response_format="diarized_json",
                chunking_strategy="auto",
            )
        payload = transcript.model_dump() if hasattr(transcript, "model_dump") else dict(transcript)
        chunk_text = apply_jargon_normalization(str(payload.get("text") or "").strip())
        if chunk_text:
            combined_text.append(chunk_text)
        for seg_index, segment in enumerate(payload.get("segments") or []):
            segment = dict(segment)
            raw_speaker = segment.get("speaker") or "Speaker"
            speaker = raw_speaker if len(audio_parts) == 1 else f"Chunk {chunk_index + 1} · {raw_speaker}"
            start = float(segment.get("start") or 0) + offset
            end = float(segment.get("end") or 0) + offset
            combined_segments.append({
                "id": segment.get("id") or f"seg_{chunk_index}_{seg_index}",
                "speaker": speaker,
                "start": start,
                "end": end,
                "text": apply_jargon_normalization(str(segment.get("text") or "").strip()),
            })
            duration = max(duration, end)

    return {
        "text": "\n".join(combined_text).strip(),
        "segments": combined_segments,
        "duration": duration,
        "chunk_count": len(audio_parts),
        "model": "gpt-4o-transcribe-diarize",
    }


def format_transcript_text(transcript_payload):
    lines = []
    for segment in transcript_payload.get("segments") or []:
        start = int(float(segment.get("start") or 0))
        minute, second = divmod(start, 60)
        lines.append(f"[{minute:02d}:{second:02d}] {segment.get('speaker')}: {segment.get('text')}")
    return "\n".join(lines)


def analyze_session_transcript(transcript_payload, candidates):
    segment_text = format_transcript_text(transcript_payload)
    if len(segment_text) > 140000:
        segment_text = segment_text[:140000]

    candidate_payload = json.dumps(candidates, default=str)[:50000]
    instructions = """
You are CMD Sally's post-meeting intelligence engine.
Analyze the speaker-labelled sales meeting transcript and compare it with the supplied
LIVE Salesforce open-opportunity candidates.

Rules:
- Never invent a Salesforce opportunity. linked_opportunity_id must be null or exactly
  one candidate id supplied below.
- Link only when the transcript provides meaningful evidence of the same customer/deal.
- A confidence >= 0.82 should mean a strong match suitable for automatic session linking.
- Lower-confidence plausible matches may still be returned as suggestions.
- Summaries must distinguish customer needs from seller commitments.
- Keep follow-ups concrete and short.
- Do not perform Salesforce writes. This step only links CMD Sally's Session metadata.
"""
    response = openai_client.responses.parse(
        model="gpt-5.6-terra",
        reasoning={"effort": "medium"},
        store=False,
        input=[
            {"role": "developer", "content": instructions + "\n\n" + configurable_context_prompt()},
            {
                "role": "user",
                "content": (
                    "LIVE SALESFORCE OPEN OPPORTUNITIES:\n" + candidate_payload
                    + "\n\nDIARIZED TRANSCRIPT:\n" + segment_text
                ),
            },
        ],
        text_format=SessionIntelligence,
    )
    parsed = response.output_parsed
    if parsed is None:
        raise RuntimeError("Meeting intelligence model returned no structured result.")
    return parsed.model_dump()


def process_session(session_id, owner_oid, salesforce_username):
    try:
        row = owner_session_row(session_id, owner_oid)
        audio_path = row["audio_path"]
        if not audio_path or not Path(audio_path).exists():
            raise RuntimeError("Session audio file is missing.")

        with session_db() as conn:
            conn.execute(
                "UPDATE sessions SET status=?, processing_error=NULL, updated_at=? WHERE session_id=?",
                ("transcribing", utc_now_iso(), session_id),
            )
            conn.commit()

        session_dir = Path(audio_path).parent
        processing_dir = session_dir / "processing"
        audio_parts = split_audio_if_needed(audio_path, processing_dir)
        transcript_payload = diarize_audio_files(audio_parts)

        transcript_json_path = session_dir / "transcript.json"
        transcript_text_path = session_dir / "transcript.txt"
        transcript_json_path.write_text(json.dumps(transcript_payload, indent=2), encoding="utf-8")
        transcript_text_path.write_text(format_transcript_text(transcript_payload), encoding="utf-8")

        with session_db() as conn:
            conn.execute(
                "UPDATE sessions SET status=?, transcript_json_path=?, transcript_text_path=?, updated_at=? WHERE session_id=?",
                ("analyzing", str(transcript_json_path), str(transcript_text_path), utc_now_iso(), session_id),
            )
            conn.commit()

        sf = get_salesforce_access_token(salesforce_username)
        candidates = open_opportunity_candidates(sf, salesforce_username)
        intelligence = analyze_session_transcript(transcript_payload, candidates)

        candidate_by_id = {c["id"]: c for c in candidates if c.get("id")}
        proposed_id = intelligence.get("linked_opportunity_id")
        confidence = max(0.0, min(float(intelligence.get("link_confidence") or 0), 1.0))
        if proposed_id not in candidate_by_id:
            proposed_id = None
            confidence = 0.0

        linked_id = proposed_id if proposed_id and confidence >= SESSION_AUTO_LINK_THRESHOLD else None
        linked_name = candidate_by_id.get(linked_id, {}).get("name") if linked_id else None
        suggested_id = proposed_id if proposed_id and not linked_id else None
        suggested_name = candidate_by_id.get(suggested_id, {}).get("name") if suggested_id else None

        summary_json_path = session_dir / "summary.json"
        summary_json_path.write_text(json.dumps(intelligence, indent=2), encoding="utf-8")

        with session_db() as conn:
            conn.execute(
                """
                UPDATE sessions
                SET status=?, title=?, summary_json_path=?, linked_opportunity_id=?, linked_opportunity_name=?,
                    link_confidence=?, suggested_opportunity_id=?, suggested_opportunity_name=?, suggested_confidence=?,
                    link_reason=?, processing_error=NULL, updated_at=?
                WHERE session_id=?
                """,
                (
                    "ready",
                    (intelligence.get("title") or "Sales session")[:240],
                    str(summary_json_path),
                    linked_id,
                    linked_name,
                    confidence if linked_id else None,
                    suggested_id,
                    suggested_name,
                    confidence if suggested_id else None,
                    str(intelligence.get("link_reason") or "")[:2000],
                    utc_now_iso(),
                    session_id,
                ),
            )
            conn.commit()
        audit_log("session_ready", owner_oid, salesforce_username, None, "Session processing completed", {"session_id": session_id, "linked_opportunity_id": linked_id})

    except Exception as exc:
        try:
            with session_db() as conn:
                conn.execute(
                    "UPDATE sessions SET status=?, processing_error=?, updated_at=? WHERE session_id=?",
                    ("error", str(exc)[:4000], utc_now_iso(), session_id),
                )
                conn.commit()
        except Exception:
            pass
        audit_log("session_error", owner_oid, salesforce_username, None, "Session processing failed", {"session_id": session_id, "error": str(exc)[:2000]})


SESSION_PROCESSING_IDS = set()
SESSION_PROCESSING_LOCK = threading.Lock()


def _session_processing_worker(session_id, owner_oid, salesforce_username):
    try:
        process_session(session_id, owner_oid, salesforce_username)
    finally:
        with SESSION_PROCESSING_LOCK:
            SESSION_PROCESSING_IDS.discard(session_id)


def launch_session_processing(session_id, owner_oid, salesforce_username):
    with SESSION_PROCESSING_LOCK:
        if session_id in SESSION_PROCESSING_IDS:
            return False
        SESSION_PROCESSING_IDS.add(session_id)

    thread = threading.Thread(
        target=_session_processing_worker,
        args=(session_id, owner_oid, salesforce_username),
        daemon=True,
        name=f"session-{session_id}",
    )
    thread.start()
    return True


def insert_or_replace_uploaded_session(
    session_id,
    claims,
    salesforce_username,
    metadata,
    audio_path,
    audio_bytes,
    actual_location,
    effective_location,
):
    now = utc_now_iso()
    voicepuck = metadata.get("voicepuck") or {
        "assigned": False,
        "connected": False,
        "device_id": None,
    }
    with session_db() as conn:
        conn.execute(
            """
            INSERT INTO sessions (
                session_id, owner_oid, salesforce_username, title, status, source,
                started_at, ended_at, duration_ms, audio_path, audio_bytes,
                actual_location_json, effective_location_json, voicepuck_json,
                processing_error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                owner_oid=excluded.owner_oid,
                salesforce_username=excluded.salesforce_username,
                status=excluded.status,
                source=excluded.source,
                started_at=excluded.started_at,
                ended_at=excluded.ended_at,
                duration_ms=excluded.duration_ms,
                audio_path=excluded.audio_path,
                audio_bytes=excluded.audio_bytes,
                actual_location_json=excluded.actual_location_json,
                effective_location_json=excluded.effective_location_json,
                voicepuck_json=excluded.voicepuck_json,
                processing_error=NULL,
                updated_at=excluded.updated_at
            """,
            (
                session_id,
                claims.get("oid"),
                salesforce_username,
                metadata.get("title") or "Processing session",
                "uploaded",
                metadata.get("source") or "iphone",
                metadata.get("started_at"),
                metadata.get("ended_at"),
                int(metadata.get("duration_ms") or 0),
                str(audio_path),
                int(audio_bytes),
                json.dumps(actual_location) if actual_location else None,
                json.dumps(effective_location) if effective_location else None,
                json.dumps(voicepuck),
                now,
                now,
            ),
        )
        conn.commit()


def get_session_open_opportunity(sf, salesforce_username, opportunity_id):
    safe_username = soql_escape(salesforce_username)
    safe_id = soql_escape(opportunity_id)
    soql = (
        "SELECT Id, Name, StageName, Amount, CloseDate, Account.Name FROM Opportunity "
        f"WHERE Id='{safe_id}' AND Owner.Username='{safe_username}' AND IsClosed=false LIMIT 1"
    )
    records = salesforce_query(sf["access_token"], sf["instance_url"], soql).get("records", [])
    if not records:
        raise ValueError("Open opportunity not found in the authenticated user's scope.")
    row = records[0]
    return {
        "id": row.get("Id"),
        "name": row.get("Name"),
        "stage": row.get("StageName"),
        "amount": row.get("Amount"),
        "close_date": row.get("CloseDate"),
        "account": (row.get("Account") or {}).get("Name"),
    }


# ============================================================
# SESSION SOFT DELETE / DEMO ARCHIVE
# ============================================================

def _session_row_any(session_id, owner_oid=None):
    sid = safe_session_id(session_id)
    with session_db() as conn:
        if owner_oid is None:
            row = conn.execute("SELECT * FROM sessions WHERE session_id=?", (sid,)).fetchone()
        else:
            row = conn.execute("SELECT * FROM sessions WHERE session_id=? AND owner_oid=?", (sid, str(owner_oid))).fetchone()
    return row


def _remap_session_path(path_value, old_root, new_root):
    if not path_value:
        return None
    try:
        p = Path(path_value)
        relative = p.relative_to(old_root)
        return str(new_root / relative)
    except Exception:
        return path_value


def archive_session(session_id, owner_oid, deleted_by):
    row = _session_row_any(session_id, owner_oid)
    if not row or row["deleted_at"]:
        raise ValueError("Session not found.")
    if row["status"] in {"uploaded", "transcribing", "analyzing"}:
        raise ValueError("Wait for Session processing to finish before deleting it.")

    safe_owner = re.sub(r"[^A-Za-z0-9_-]", "_", str(owner_oid))
    source_root = Path(row["audio_path"]).parent if row["audio_path"] else (SESSION_AUDIO_ROOT / safe_owner / session_id)
    archive_root = SESSION_DELETED_ROOT / safe_owner / session_id
    if archive_root.exists():
        archive_root = SESSION_DELETED_ROOT / safe_owner / f"{session_id}_{int(time.time())}"
    archive_root.parent.mkdir(parents=True, exist_ok=True)

    if source_root.exists():
        shutil.move(str(source_root), str(archive_root))

    now = utc_now_iso()
    updated_paths = {
        "audio_path": _remap_session_path(row["audio_path"], source_root, archive_root),
        "transcript_json_path": _remap_session_path(row["transcript_json_path"], source_root, archive_root),
        "transcript_text_path": _remap_session_path(row["transcript_text_path"], source_root, archive_root),
        "summary_json_path": _remap_session_path(row["summary_json_path"], source_root, archive_root),
    }
    with session_db() as conn:
        conn.execute(
            """UPDATE sessions SET audio_path=?, transcript_json_path=?, transcript_text_path=?, summary_json_path=?,
               deleted_at=?, deleted_by=?, deleted_archive_path=?, updated_at=? WHERE session_id=? AND owner_oid=?""",
            (updated_paths["audio_path"], updated_paths["transcript_json_path"], updated_paths["transcript_text_path"],
             updated_paths["summary_json_path"], now, str(deleted_by or owner_oid), str(archive_root), now, session_id, str(owner_oid)),
        )
        conn.commit()
    audit_log("session_deleted", owner_oid, row["salesforce_username"], None, "Session moved to demo deleted archive", {"session_id": session_id})
    return True


def restore_archived_session(session_id):
    row = _session_row_any(session_id)
    if not row or not row["deleted_at"]:
        raise ValueError("Deleted Session not found.")
    owner_oid = row["owner_oid"]
    safe_owner = re.sub(r"[^A-Za-z0-9_-]", "_", str(owner_oid))
    archive_root = Path(row["deleted_archive_path"] or "")
    active_root = SESSION_AUDIO_ROOT / safe_owner / session_id
    if active_root.exists():
        raise ValueError("An active Session directory with this id already exists.")
    active_root.parent.mkdir(parents=True, exist_ok=True)
    if archive_root.exists():
        shutil.move(str(archive_root), str(active_root))
    now = utc_now_iso()
    with session_db() as conn:
        conn.execute(
            """UPDATE sessions SET audio_path=?, transcript_json_path=?, transcript_text_path=?, summary_json_path=?,
               deleted_at=NULL, deleted_by=NULL, deleted_archive_path=NULL, updated_at=? WHERE session_id=?""",
            (_remap_session_path(row["audio_path"], archive_root, active_root),
             _remap_session_path(row["transcript_json_path"], archive_root, active_root),
             _remap_session_path(row["transcript_text_path"], archive_root, active_root),
             _remap_session_path(row["summary_json_path"], archive_root, active_root), now, session_id),
        )
        conn.commit()
    audit_log("session_restored", owner_oid, row["salesforce_username"], None, "Deleted Session restored by admin", {"session_id": session_id})
    return True


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def root():
    return jsonify({
        "service": "CMD Sally API",
        "status": "running",
        "version": "cmd-sally-v4-demo",
    })


@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "version": "cmd-sally-v4-demo",
        "session_storage_root": str(SESSION_STORAGE_ROOT),
        "persistent_disk_expected": str(SESSION_STORAGE_ROOT).startswith("/var/data"),
        "demo_geo_enabled": feature_enabled("demo_geography", DEMO_GEO_ENABLED),
    })


@app.get("/me")
@require_auth
def me():
    claims = request.user_claims

    return jsonify({
        "authenticated": True,
        "name": claims.get("name"),
        "username": claims.get("preferred_username"),
        "oid": claims.get("oid"),
        "tenant_id": claims.get("tid"),
        "scope": claims.get("scp"),
        "audience": claims.get("aud"),
        "token_version": claims.get("ver"),
    })


@app.get("/capabilities")
@require_auth
def capabilities():
    """Return current demo capabilities and client speech hints to the mobile app."""
    return jsonify({
        "capabilities": current_capabilities(),
        "speech_context": client_speech_context(),
    })


@app.get("/salesforce/me")
@require_auth
def salesforce_me():
    claims = request.user_claims
    salesforce_username = claims.get("preferred_username")

    if not salesforce_username:
        return jsonify({
            "error": "preferred_username_missing"
        }), 400

    try:
        sf = get_salesforce_access_token(salesforce_username)
    except Exception as e:
        return jsonify({
            "microsoft_authenticated": True,
            "salesforce_authenticated": False,
            "microsoft_username": salesforce_username,
            "salesforce_username": salesforce_username,
            "error": str(e),
        }), 502

    safe_username = soql_escape(salesforce_username)

    soql = (
        "SELECT Id, Name, StageName, Amount, CloseDate "
        "FROM Opportunity "
        f"WHERE Owner.Username = '{safe_username}' "
        "ORDER BY CloseDate ASC "
        "LIMIT 100"
    )

    try:
        data = salesforce_query(
            sf["access_token"],
            sf["instance_url"],
            soql,
        )
    except Exception as e:
        return jsonify({
            "microsoft_authenticated": True,
            "salesforce_authenticated": True,
            "salesforce_query_success": False,
            "microsoft_username": salesforce_username,
            "salesforce_username": salesforce_username,
            "error": str(e),
        }), 403

    opportunities = [
        {
            "id": row.get("Id"),
            "name": row.get("Name"),
            "stage": row.get("StageName"),
            "amount": row.get("Amount"),
            "close_date": row.get("CloseDate"),
        }
        for row in data.get("records", [])
    ]

    return jsonify({
        "microsoft": {
            "name": claims.get("name"),
            "username": salesforce_username,
            "oid": claims.get("oid"),
            "tenant_id": claims.get("tid"),
        },
        "salesforce": {
            "connected": True,
            "username": salesforce_username,
            "instance": sf["instance_url"],
        },
        "opportunity_count": len(opportunities),
        "opportunities": opportunities,
    })


# ============================================================
# CHAT EXECUTION + LIVE STATUS JOBS
# ============================================================

CHAT_JOBS = {}
CHAT_JOBS_LOCK = threading.Lock()
CHAT_JOB_SEMAPHORE = threading.BoundedSemaphore(CHAT_JOB_MAX_CONCURRENT)


def _cleanup_chat_jobs():
    cutoff = time.time() - CHAT_JOB_TTL_SECONDS
    with CHAT_JOBS_LOCK:
        stale = [job_id for job_id, job in CHAT_JOBS.items() if job.get("updated_ts", 0) < cutoff and job.get("state") in {"completed", "failed"}]
        for job_id in stale:
            CHAT_JOBS.pop(job_id, None)


def _job_public(job, include_result=False):
    payload = {
        "job_id": job["job_id"],
        "state": job["state"],
        "current_status": job.get("current_status"),
        "status_code": job.get("status_code"),
        "events": job.get("events", [])[-20:],
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
    }
    if job.get("error"):
        payload["error"] = job["error"]
    if include_result and job.get("state") == "completed":
        payload["result"] = job.get("result")
    return payload


def set_chat_job_status(job_id, code, message, detail=None):
    now_iso = utc_now_iso()
    with CHAT_JOBS_LOCK:
        job = CHAT_JOBS.get(job_id)
        if not job:
            return
        job["status_code"] = code
        job["current_status"] = message
        job["updated_at"] = now_iso
        job["updated_ts"] = time.time()
        event = {"code": code, "message": message, "at": now_iso}
        if detail:
            event["detail"] = detail
        events = job.setdefault("events", [])
        if not events or events[-1].get("code") != code or events[-1].get("message") != message:
            events.append(event)
            del events[:-30]


def run_chat_logic(body, claims, progress_callback=None, request_id=None):
    user_message = (body.get("message") or "").strip()
    history = normalize_conversation_history(body.get("history"))
    client_context = normalize_client_context(body.get("client_context"))
    if not user_message:
        raise ValueError("message_required")

    salesforce_username = claims.get("preferred_username")
    if not salesforce_username:
        raise ValueError("preferred_username_missing")

    emit_progress(progress_callback, "routing", "Understanding your request…")
    decision = route_or_answer(user_message, history=history, client_context=client_context)
    route_data = decision.model_dump()

    if decision.needs_salesforce and not feature_enabled("salesforce_reads", True):
        raise RuntimeError("Salesforce reads are temporarily disabled by the demo administrator.")
    if decision.needs_write and not feature_enabled("salesforce_writes", True):
        raise RuntimeError("Salesforce writes are temporarily disabled by the demo administrator.")
    if decision.needs_web and not feature_enabled("web_research", True):
        raise RuntimeError("Web research is temporarily disabled by the demo administrator.")
    if decision.route in {"web_research", "deep_complex"} and not feature_enabled("long_research", True):
        raise RuntimeError("Long research jobs are temporarily disabled by the demo administrator.")

    if decision.action == "answer":
        emit_progress(progress_callback, "finalizing", "Preparing Sally's answer…")
        return {
            "status": "answered", "user": salesforce_username, "router_model": "gpt-5.6-luna",
            "route": route_data, "execution_model": "gpt-5.6-luna", "answer": decision.answer,
            "display_text": decision.answer, "speech_text": decision.answer, "conversation_text": decision.answer,
            "ui_blocks": [], "capabilities": current_capabilities(), "tool_trace": [], "web_used": False,
            "web_sources": [], "pending_actions": [], "confirmation_required": False,
            "conversation_history_used": len(history),
        }

    sf = None
    if decision.needs_salesforce:
        emit_progress(progress_callback, "salesforce_auth", "Connecting to Salesforce…")
        sf = get_salesforce_access_token(salesforce_username)

    location_context = None
    if sf is not None and client_context.get("location") and feature_enabled("location", True):
        emit_progress(progress_callback, "location", "Resolving your CRM location…")
        location_context = resolve_location_context(sf, salesforce_username, client_context, claims)

    result = execute_agent(
        user_message, decision, sf, salesforce_username, claims,
        history=history, client_context=client_context, location_context=location_context,
        progress_callback=progress_callback, request_id=request_id,
    )
    response_body = {
        "status": "confirmation_required" if result["confirmation_required"] else "answered",
        "user": salesforce_username, "router_model": "gpt-5.6-luna", "route": route_data,
        "execution_model": result["execution_model"], "execution_effort": result["reasoning_effort"],
        "tool_rounds": result["tool_rounds"], "tool_trace": result["tool_trace"],
        "web_used": result["web_used"], "web_search_trace": result["web_search_trace"],
        "web_sources": result["web_sources"], "pending_actions": result["pending_actions"],
        "confirmation_required": result["confirmation_required"], "answer": result["answer"],
        "display_text": result["display_text"], "speech_text": result["speech_text"],
        "conversation_text": result["conversation_text"], "ui_blocks": result["ui_blocks"],
        "capabilities": current_capabilities(), "location_context": result.get("location_context"),
        "conversation_history_used": len(history),
    }
    if result["confirmation_token"]:
        response_body["confirmation_token"] = result["confirmation_token"]
    return response_body


def _chat_job_worker(job_id, body, claims):
    owner_oid = claims.get("oid")
    username = claims.get("preferred_username")
    try:
        set_chat_job_status(job_id, "queued", "Waiting for Sally's worker…")
        with CHAT_JOB_SEMAPHORE:
            set_chat_job_status(job_id, "started", "Sally is starting…")
            result = run_chat_logic(
                body, claims,
                progress_callback=lambda code, message, detail=None: set_chat_job_status(job_id, code, message, detail),
                request_id=job_id,
            )
            with CHAT_JOBS_LOCK:
                job = CHAT_JOBS.get(job_id)
                if job:
                    job["state"] = "completed"
                    job["result"] = result
                    job["current_status"] = None
                    job["status_code"] = "completed"
                    job["updated_at"] = utc_now_iso()
                    job["updated_ts"] = time.time()
            audit_log("chat_completed", owner_oid, username, job_id, "Chat request completed", {
                "route": (result.get("route") or {}).get("route"),
                "execution_model": result.get("execution_model"),
                "tool_count": len(result.get("tool_trace") or []),
                "web_used": bool(result.get("web_used")),
            })
    except Exception as exc:
        with CHAT_JOBS_LOCK:
            job = CHAT_JOBS.get(job_id)
            if job:
                job["state"] = "failed"
                job["error"] = {"code": "chat_failed", "message": str(exc)[:1200]}
                job["current_status"] = None
                job["status_code"] = "failed"
                job["updated_at"] = utc_now_iso()
                job["updated_ts"] = time.time()
        audit_log("chat_failed", owner_oid, username, job_id, "Chat request failed", {"error": str(exc)[:2000]})


@app.post("/chat/start")
@require_auth
def chat_start():
    _cleanup_chat_jobs()
    body = request.get_json(silent=True) or {}
    if not (body.get("message") or "").strip():
        return jsonify({"error": "message_required"}), 400
    claims = dict(request.user_claims)
    owner_oid = claims.get("oid")
    if not owner_oid:
        return jsonify({"error": "oid_missing"}), 400
    with CHAT_JOBS_LOCK:
        active = sum(1 for j in CHAT_JOBS.values() if j.get("owner_oid") == owner_oid and j.get("state") in {"queued", "running"})
        if active >= 3:
            return jsonify({"error": "too_many_active_requests", "details": "Wait for one of Sally's active requests to finish."}), 429
        job_id = "req_" + uuid.uuid4().hex[:20]
        now = utc_now_iso()
        CHAT_JOBS[job_id] = {
            "job_id": job_id, "owner_oid": owner_oid, "salesforce_username": claims.get("preferred_username"),
            "state": "running", "status_code": "accepted", "current_status": "Sending to Sally…",
            "events": [{"code": "accepted", "message": "Sending to Sally…", "at": now}],
            "result": None, "error": None, "created_at": now, "updated_at": now, "updated_ts": time.time(),
        }
    audit_log("chat_started", owner_oid, claims.get("preferred_username"), job_id, "Chat request started", {})
    threading.Thread(target=_chat_job_worker, args=(job_id, body, claims), daemon=True, name=f"chat-{job_id}").start()
    with CHAT_JOBS_LOCK:
        return jsonify(_job_public(CHAT_JOBS[job_id])), 202


@app.get("/chat/jobs/<job_id>")
@require_auth
def chat_job_status(job_id):
    _cleanup_chat_jobs()
    with CHAT_JOBS_LOCK:
        job = CHAT_JOBS.get(job_id)
        if not job or job.get("owner_oid") != request.user_claims.get("oid"):
            return jsonify({"error": "job_not_found"}), 404
        return jsonify(_job_public(job, include_result=True))


@app.post("/chat")
@require_auth
def chat():
    """Backward-compatible synchronous endpoint. V4 mobile uses /chat/start."""
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(run_chat_logic(body, request.user_claims))
    except ValueError as exc:
        code = str(exc)
        return jsonify({"error": code}), 400
    except Exception as exc:
        return jsonify({"error": "chat_failed", "details": str(exc)}), 500


@app.post("/location/resolve")
@require_auth
def resolve_device_location():
    if not feature_enabled("location", True):
        return jsonify({"error": "location_disabled"}), 403
    body = request.get_json(silent=True) or {}
    client_context = normalize_client_context(body.get("client_context") or body)
    if not client_context.get("location"):
        return jsonify({"error": "location_required"}), 400

    claims = request.user_claims
    salesforce_username = claims.get("preferred_username")
    if not salesforce_username:
        return jsonify({"error": "preferred_username_missing"}), 400

    try:
        sf = get_salesforce_access_token(salesforce_username)
        context = resolve_location_context(sf, salesforce_username, client_context, claims)
        if context is None:
            return jsonify({"error": "invalid_location"}), 400
        return jsonify({"location_context": context})
    except Exception as exc:
        return jsonify({"error": "location_resolve_failed", "details": str(exc)}), 400


@app.get("/sessions")
@require_auth
def list_sessions():
    owner_oid = request.user_claims.get("oid")
    with session_db() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions WHERE owner_oid=? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 100",
            (owner_oid,),
        ).fetchall()
    return jsonify({
        "sessions": [session_row_to_dict(row, include_summary=False) for row in rows],
        "voicepuck": {"assigned": False, "connected": False, "device_id": None},
        "storage_root": str(SESSION_STORAGE_ROOT),
    })


@app.post("/sessions/upload")
@require_auth
def upload_session():
    if not feature_enabled("session_recording", True):
        return jsonify({"error": "session_recording_disabled"}), 403
    claims = request.user_claims
    owner_oid = claims.get("oid")
    salesforce_username = claims.get("preferred_username")
    if not owner_oid or not salesforce_username:
        return jsonify({"error": "identity_missing"}), 400

    audio = request.files.get("audio")
    if audio is None:
        return jsonify({"error": "audio_required"}), 400

    try:
        metadata = json.loads(request.form.get("metadata") or "{}")
        session_id = safe_session_id(metadata.get("session_id") or request.form.get("session_id"))
        user_dir = SESSION_AUDIO_ROOT / re.sub(r"[^A-Za-z0-9_-]", "_", owner_oid)
        session_dir = user_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        audio_path = session_dir / "original.m4a"
        audio.save(str(audio_path))
        audio_bytes = audio_path.stat().st_size

        raw_location = metadata.get("location") if isinstance(metadata.get("location"), dict) else None
        client_context = {
            "location": raw_location,
            "geo_session_id": metadata.get("geo_session_id") or session_id,
        } if raw_location else {}
        location_context = None
        if raw_location:
            sf = get_salesforce_access_token(salesforce_username)
            location_context = resolve_location_context(sf, salesforce_username, client_context, claims)

        insert_or_replace_uploaded_session(
            session_id,
            claims,
            salesforce_username,
            metadata,
            audio_path,
            audio_bytes,
            (location_context or {}).get("actual") if location_context else raw_location,
            (location_context or {}).get("effective") if location_context else raw_location,
        )
        launch_session_processing(session_id, owner_oid, salesforce_username)
        row = owner_session_row(session_id, owner_oid)
        return jsonify({
            "status": "uploaded",
            "session": session_row_to_dict(row),
            "location_context": location_context,
        }), 202
    except Exception as exc:
        return jsonify({"error": "session_upload_failed", "details": str(exc)}), 400


@app.delete("/sessions/<session_id>")
@require_auth
def delete_session(session_id):
    if not feature_enabled("session_soft_delete", True):
        return jsonify({"error": "session_delete_disabled"}), 403
    claims = request.user_claims
    try:
        archive_session(session_id, claims.get("oid"), claims.get("preferred_username") or claims.get("oid"))
        return jsonify({"status": "deleted", "session_id": session_id})
    except ValueError as exc:
        return jsonify({"error": "session_delete_failed", "details": str(exc)}), 409
    except Exception as exc:
        return jsonify({"error": "session_delete_failed", "details": str(exc)}), 400


@app.get("/sessions/<session_id>")
@require_auth
def get_session(session_id):
    try:
        row = owner_session_row(session_id, request.user_claims.get("oid"))
        return jsonify({"session": session_row_to_dict(row, include_summary=True)})
    except Exception as exc:
        return jsonify({"error": "session_not_found", "details": str(exc)}), 404


@app.get("/sessions/<session_id>/transcript")
@require_auth
def get_session_transcript(session_id):
    try:
        row = owner_session_row(session_id, request.user_claims.get("oid"))
        payload = read_json_file(row["transcript_json_path"], None)
        if payload is None:
            return jsonify({"error": "transcript_not_ready", "status": row["status"]}), 409
        return jsonify({"session_id": session_id, **payload})
    except Exception as exc:
        return jsonify({"error": "transcript_failed", "details": str(exc)}), 404


@app.get("/sessions/<session_id>/audio")
@require_auth
def get_session_audio(session_id):
    try:
        row = owner_session_row(session_id, request.user_claims.get("oid"))
        path = row["audio_path"]
        if not path or not Path(path).exists():
            return jsonify({"error": "audio_not_found"}), 404
        return send_file(path, mimetype="audio/mp4", conditional=True)
    except Exception as exc:
        return jsonify({"error": "audio_failed", "details": str(exc)}), 404


@app.post("/sessions/<session_id>/retry")
@require_auth
def retry_session(session_id):
    claims = request.user_claims
    try:
        row = owner_session_row(session_id, claims.get("oid"))
        started = launch_session_processing(
            session_id, claims.get("oid"), claims.get("preferred_username")
        )
        return jsonify({
            "status": "processing_restarted" if started else "already_processing"
        }), 202
    except Exception as exc:
        return jsonify({"error": "retry_failed", "details": str(exc)}), 400


@app.get("/sessions/link-options")
@require_auth
def session_link_options():
    claims = request.user_claims
    try:
        sf = get_salesforce_access_token(claims.get("preferred_username"))
        candidates = open_opportunity_candidates(sf, claims.get("preferred_username"))
        return jsonify({"opportunities": candidates})
    except Exception as exc:
        return jsonify({"error": "link_options_failed", "details": str(exc)}), 400


@app.post("/sessions/<session_id>/link-opportunity")
@require_auth
def link_session_opportunity(session_id):
    claims = request.user_claims
    body = request.get_json(silent=True) or {}
    opportunity_id = body.get("opportunity_id")
    try:
        owner_session_row(session_id, claims.get("oid"))
        if opportunity_id:
            sf = get_salesforce_access_token(claims.get("preferred_username"))
            opp = get_session_open_opportunity(sf, claims.get("preferred_username"), opportunity_id)
            linked_id, linked_name = opp["id"], opp["name"]
        else:
            linked_id, linked_name = None, None
        with session_db() as conn:
            conn.execute(
                """
                UPDATE sessions SET linked_opportunity_id=?, linked_opportunity_name=?, link_confidence=?,
                    suggested_opportunity_id=NULL, suggested_opportunity_name=NULL, suggested_confidence=NULL,
                    updated_at=? WHERE session_id=? AND owner_oid=?
                """,
                (linked_id, linked_name, 1.0 if linked_id else None, utc_now_iso(), session_id, claims.get("oid")),
            )
            conn.commit()
        row = owner_session_row(session_id, claims.get("oid"))
        return jsonify({"session": session_row_to_dict(row, include_summary=True)})
    except Exception as exc:
        return jsonify({"error": "link_failed", "details": str(exc)}), 400


@app.post("/confirm")
@require_auth
def confirm():
    if not feature_enabled("salesforce_writes", True):
        return jsonify({"error": "salesforce_writes_disabled"}), 403
    body = request.get_json(silent=True) or {}
    confirmation_token = body.get("confirmation_token")

    if not confirmation_token:
        return jsonify({
            "error": "confirmation_token_required"
        }), 400

    try:
        payload = decode_confirmation_token(
            confirmation_token
        )

        results = execute_confirmed_actions(
            request.user_claims,
            payload,
        )
        for item in results:
            audit_log(
                "salesforce_write",
                owner_oid=request.user_claims.get("oid"),
                salesforce_username=request.user_claims.get("preferred_username"),
                summary=f"{item.get('action') or 'salesforce_write'} confirmed",
                details={
                    "action": item.get("action"),
                    "field_name": item.get("field_name"),
                    "status": item.get("status"),
                    "opportunity_id": item.get("opportunity_id"),
                    "event_id": item.get("event_id"),
                },
            )

        return jsonify({
            "status": "confirmed",
            "affected_count": len(results),
            "updated_count": len(results),
            "results": results,
        })

    except jwt.ExpiredSignatureError:
        return jsonify({
            "error": "confirmation_expired",
            "details": (
                "The write confirmation expired. "
                "Ask the assistant to prepare the changes again."
            ),
        }), 400

    except Exception as e:
        return jsonify({
            "error": "confirmation_failed",
            "details": str(e),
        }), 400


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        if request.path.startswith("/admin") and not request.path.startswith("/admin/api"):
            return error
        return jsonify({"error": error.name.lower().replace(" ", "_"), "details": error.description}), error.code
    audit_log("unhandled_error", summary="Unhandled backend exception", details={"path": request.path, "error": str(error)[:2000]})
    return jsonify({"error": "internal_error", "details": "CMD Sally could not complete this request."}), 500


# ============================================================
# DEMO ADMIN CONSOLE
# ============================================================

ADMIN_LOGIN_ATTEMPTS = {}
ADMIN_LOGIN_LOCK = threading.Lock()


def admin_configured():
    return bool(ADMIN_USERNAME and ADMIN_PASSWORD and ADMIN_SESSION_SECRET)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not admin_configured():
            return "CMD Sally Admin is not configured. Set ADMIN_USERNAME, ADMIN_PASSWORD and ADMIN_SESSION_SECRET in Render.", 503
        if not session.get("cmd_sally_admin"):
            return redirect(url_for("admin_login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def admin_api_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not admin_configured():
            return jsonify({"error": "admin_not_configured"}), 503
        if not session.get("cmd_sally_admin"):
            return jsonify({"error": "admin_auth_required"}), 401
        return fn(*args, **kwargs)
    return wrapper


def admin_mutation_required(fn):
    @wraps(fn)
    @admin_api_required
    def wrapper(*args, **kwargs):
        expected = session.get("admin_csrf") or ""
        provided = request.headers.get("X-CSRF-Token", "")
        if not expected or not hmac.compare_digest(expected, provided):
            return jsonify({"error": "csrf_failed"}), 403
        return fn(*args, **kwargs)
    return wrapper


def _admin_login_allowed(ip):
    now = time.time()
    with ADMIN_LOGIN_LOCK:
        recent = [t for t in ADMIN_LOGIN_ATTEMPTS.get(ip, []) if now - t < 600]
        ADMIN_LOGIN_ATTEMPTS[ip] = recent
        return len(recent) < 6


def _admin_record_login_failure(ip):
    with ADMIN_LOGIN_LOCK:
        ADMIN_LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())


def _row_to_workflow(row):
    d = dict(row)
    d["triggers"] = json.loads(d.pop("triggers_json") or "[]")
    d["steps"] = json.loads(d.pop("steps_json") or "[]")
    d["tools"] = json.loads(d.pop("tools_json") or "[]")
    d["enabled"] = bool(d["enabled"])
    d["confirmation_required"] = bool(d["confirmation_required"])
    return d


def _row_to_jargon(row):
    d = dict(row)
    d["aliases"] = json.loads(d.pop("aliases_json") or "[]")
    d["enabled"] = bool(d["enabled"])
    return d


@app.get("/admin/login")
def admin_login():
    if session.get("cmd_sally_admin"):
        return redirect(url_for("admin_home"))
    return render_template("admin_login.html", configured=admin_configured(), error=None)


@app.post("/admin/login")
def admin_login_post():
    if not admin_configured():
        return render_template("admin_login.html", configured=False, error="Admin environment variables are not configured."), 503
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not _admin_login_allowed(ip):
        return render_template("admin_login.html", configured=True, error="Too many failed attempts. Try again later."), 429
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    valid = hmac.compare_digest(username, ADMIN_USERNAME) and hmac.compare_digest(password, ADMIN_PASSWORD)
    if not valid:
        _admin_record_login_failure(ip)
        audit_log("admin_login_failed", summary="Admin login failed", details={"ip": ip})
        return render_template("admin_login.html", configured=True, error="Invalid username or password."), 401
    session.clear()
    session["cmd_sally_admin"] = True
    session["admin_username"] = username
    session["admin_csrf"] = secrets.token_urlsafe(32)
    audit_log("admin_login", summary="Admin login successful", details={"ip": ip})
    return redirect(url_for("admin_home"))


@app.post("/admin/logout")
@admin_required
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.get("/admin")
@admin_required
def admin_home():
    return render_template("admin.html", csrf_token=session.get("admin_csrf"), admin_username=session.get("admin_username"))


@app.get("/admin/api/overview")
@admin_api_required
def admin_overview():
    today = datetime.now(timezone.utc).date().isoformat()
    with session_db() as conn:
        session_counts = dict(conn.execute("""SELECT
            SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) active,
            SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END) deleted,
            SUM(CASE WHEN deleted_at IS NULL AND status='error' THEN 1 ELSE 0 END) errors
            FROM sessions""").fetchone())
        audit_today = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE created_at LIKE ?", (today + "%",)).fetchone()["c"]
        requests_today = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE event_type='chat_started' AND created_at LIKE ?", (today + "%",)).fetchone()["c"]
        tool_today = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE event_type='salesforce_tool' AND created_at LIKE ?", (today + "%",)).fetchone()["c"]
        writes_today = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE event_type='salesforce_write' AND created_at LIKE ?", (today + "%",)).fetchone()["c"]
        web_today = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE event_type='web_search' AND created_at LIKE ?", (today + "%",)).fetchone()["c"]
        sessions_ready_today = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE event_type='session_ready' AND created_at LIKE ?", (today + "%",)).fetchone()["c"]
        errors_today = conn.execute("SELECT COUNT(*) c FROM audit_events WHERE event_type IN ('chat_failed','session_error') AND created_at LIKE ?", (today + "%",)).fetchone()["c"]
        users = conn.execute("""SELECT salesforce_username, owner_oid, MAX(created_at) last_seen, COUNT(*) activity_count
            FROM audit_events WHERE salesforce_username IS NOT NULL GROUP BY salesforce_username, owner_oid ORDER BY last_seen DESC LIMIT 50""").fetchall()
        event_counts = conn.execute("SELECT event_type, COUNT(*) c FROM audit_events WHERE created_at LIKE ? GROUP BY event_type ORDER BY c DESC", (today + "%",)).fetchall()
    with CHAT_JOBS_LOCK:
        jobs = [_job_public(j, include_result=False) | {"salesforce_username": j.get("salesforce_username")} for j in CHAT_JOBS.values()]
    jobs.sort(key=lambda j: j.get("updated_at") or "", reverse=True)
    return jsonify({
        "version": "cmd-sally-v4-demo", "service": "CMD Sally API", "storage_root": str(SESSION_STORAGE_ROOT),
        "persistent_disk_expected": str(SESSION_STORAGE_ROOT).startswith("/var/data"),
        "feature_flags": get_feature_flags(), "forced_demo_cluster": get_config_setting("demo_geo_force_cluster", "automatic"),
        "sessions": session_counts, "audit_events_today": audit_today, "requests_today": requests_today,
        "salesforce_tool_calls_today": tool_today, "salesforce_writes_today": writes_today,
        "web_searches_today": web_today, "sessions_ready_today": sessions_ready_today, "errors_today": errors_today,
        "users": [dict(r) for r in users], "event_counts": [dict(r) for r in event_counts], "jobs": jobs[:25],
        "models": {"orchestrator": "gpt-5.6-luna / low", "analysis": "gpt-5.6-terra", "deep": "gpt-5.6-sol", "transcription": "gpt-4o-transcribe-diarize"},
        "voicepuck": {"mode": "demo", "assigned": False, "connected": False},
    })


@app.get("/admin/api/audit")
@admin_api_required
def admin_audit():
    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    with session_db() as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    items=[]
    for row in rows:
        d=dict(row)
        d["details"] = json.loads(d.pop("details_json") or "{}")
        items.append(d)
    return jsonify({"events": items})


@app.get("/admin/api/sessions")
@admin_api_required
def admin_sessions():
    deleted = request.args.get("deleted", "false").lower() == "true"
    where = "deleted_at IS NOT NULL" if deleted else "deleted_at IS NULL"
    with session_db() as conn:
        rows = conn.execute(f"SELECT * FROM sessions WHERE {where} ORDER BY updated_at DESC LIMIT 200").fetchall()
    return jsonify({"sessions": [session_row_to_dict(row, include_summary=False) | {"owner_oid": row["owner_oid"], "salesforce_username": row["salesforce_username"], "deleted_archive_path": row["deleted_archive_path"]} for row in rows]})


@app.post("/admin/api/sessions/<session_id>/restore")
@admin_mutation_required
def admin_restore_session(session_id):
    try:
        restore_archived_session(session_id)
        return jsonify({"status": "restored", "session_id": session_id})
    except Exception as exc:
        return jsonify({"error": "restore_failed", "details": str(exc)}), 400


@app.post("/admin/api/sessions/<session_id>/retry")
@admin_mutation_required
def admin_retry_session(session_id):
    row = _session_row_any(session_id)
    if not row or row["deleted_at"]:
        return jsonify({"error": "session_not_found"}), 404
    if row["status"] in {"transcribing", "analyzing"}:
        return jsonify({"error": "session_already_processing"}), 409
    try:
        launch_session_processing(row["session_id"], row["owner_oid"], row["salesforce_username"])
        audit_log("admin_session_retry", row["owner_oid"], row["salesforce_username"], None,
                  "Admin retried Session processing", {"session_id": row["session_id"]})
        return jsonify({"status": "processing_restarted", "session_id": row["session_id"]}), 202
    except Exception as exc:
        return jsonify({"error": "session_retry_failed", "details": str(exc)}), 400


@app.get("/admin/sessions/<session_id>/audio")
@admin_required
def admin_session_audio(session_id):
    row = _session_row_any(session_id)
    if not row or not row["audio_path"] or not Path(row["audio_path"]).exists(): abort(404)
    return send_file(row["audio_path"], mimetype="audio/mp4", conditional=True)


@app.get("/admin/sessions/<session_id>/transcript")
@admin_required
def admin_session_transcript(session_id):
    row = _session_row_any(session_id)
    if not row or not row["transcript_text_path"] or not Path(row["transcript_text_path"]).exists(): abort(404)
    return send_file(row["transcript_text_path"], mimetype="text/plain")


@app.get("/admin/api/feature-flags")
@admin_api_required
def admin_feature_flags():
    return jsonify({"flags": get_feature_flags(), "forced_demo_cluster": get_config_setting("demo_geo_force_cluster", "automatic")})


@app.post("/admin/api/feature-flags")
@admin_mutation_required
def admin_update_feature_flags():
    body = request.get_json(silent=True) or {}
    allowed = {"salesforce_reads", "salesforce_writes", "web_research", "session_recording", "session_soft_delete", "location", "demo_geography", "long_research", "voice_chat"}
    with session_db() as conn:
        for key, value in (body.get("flags") or {}).items():
            if key in allowed and isinstance(value, bool):
                conn.execute("INSERT INTO config_feature_flags(key,enabled,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at", (key, int(value), utc_now_iso()))
        conn.commit()
    cluster = body.get("forced_demo_cluster")
    if cluster in {"automatic", "dallas", "houston", "austin", "chicago", "boston", "sf", "sandiego", "losangeles"}:
        set_config_setting("demo_geo_force_cluster", cluster)
    audit_log("admin_config", summary="Admin updated demo feature flags", details={"flags": body.get("flags"), "forced_demo_cluster": cluster})
    return jsonify({"flags": get_feature_flags(), "forced_demo_cluster": get_config_setting("demo_geo_force_cluster", "automatic")})


@app.get("/admin/api/workflows")
@admin_api_required
def admin_workflows():
    with session_db() as conn:
        rows=conn.execute("SELECT * FROM config_workflows ORDER BY name").fetchall()
    return jsonify({"workflows": [_row_to_workflow(r) for r in rows]})


@app.post("/admin/api/workflows")
@admin_mutation_required
def admin_save_workflow():
    body=request.get_json(silent=True) or {}
    name=str(body.get("name") or "").strip()
    if not name: return jsonify({"error":"name_required"}),400
    raw_wid = str(body.get("id") or "").strip()
    if raw_wid and not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", raw_wid):
        return jsonify({"error":"invalid_workflow_id"}),400
    wid=(raw_wid or re.sub(r"[^a-z0-9]+","_",name.lower()).strip("_") or ("wf_"+uuid.uuid4().hex[:8]))[:80]
    desc=str(body.get("description") or "").strip()[:2000]
    triggers=[str(x).strip()[:300] for x in (body.get("triggers") or []) if str(x).strip()][:30]
    steps=[str(x).strip()[:500] for x in (body.get("steps") or []) if str(x).strip()][:30]
    tools=[str(x).strip()[:100] for x in (body.get("tools") or []) if str(x).strip()][:20]
    enabled=bool(body.get("enabled",True)); confirm=bool(body.get("confirmation_required",False)); now=utc_now_iso()
    with session_db() as conn:
        existing=conn.execute("SELECT version FROM config_workflows WHERE id=?",(wid,)).fetchone()
        version=(existing["version"]+1) if existing else 1
        conn.execute("""INSERT INTO config_workflows(id,name,description,triggers_json,steps_json,tools_json,confirmation_required,enabled,version,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,triggers_json=excluded.triggers_json,steps_json=excluded.steps_json,tools_json=excluded.tools_json,confirmation_required=excluded.confirmation_required,enabled=excluded.enabled,version=excluded.version,updated_at=excluded.updated_at""",
            (wid,name,desc,json.dumps(triggers),json.dumps(steps),json.dumps(tools),int(confirm),int(enabled),version,now,now))
        conn.commit()
    audit_log("admin_workflow", summary=f"Workflow saved: {name}", details={"id":wid,"version":version,"enabled":enabled})
    return jsonify({"status":"saved","id":wid,"version":version})


@app.get("/admin/api/jargon")
@admin_api_required
def admin_jargon():
    with session_db() as conn: rows=conn.execute("SELECT * FROM config_jargon ORDER BY term").fetchall()
    return jsonify({"jargon": [_row_to_jargon(r) for r in rows]})


@app.post("/admin/api/jargon")
@admin_mutation_required
def admin_save_jargon():
    body=request.get_json(silent=True) or {}; term=str(body.get("term") or "").strip()
    if not term: return jsonify({"error":"term_required"}),400
    raw_jid = str(body.get("id") or "").strip()
    if raw_jid and not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", raw_jid):
        return jsonify({"error":"invalid_jargon_id"}),400
    jid=(raw_jid or re.sub(r"[^a-z0-9]+","_",term.lower()).strip("_") or ("j_"+uuid.uuid4().hex[:8]))[:80]
    aliases=[str(x).strip()[:200] for x in (body.get("aliases") or []) if str(x).strip()][:50]
    now=utc_now_iso()
    values=(jid,term,json.dumps(aliases),str(body.get("pronunciation") or "")[:200],str(body.get("category") or "")[:100],str(body.get("definition") or "")[:3000],str(body.get("examples") or "")[:3000],str(body.get("stt_priority") or "normal")[:30],int(bool(body.get("enabled",True))),now,now)
    with session_db() as conn:
        conn.execute("""INSERT INTO config_jargon(id,term,aliases_json,pronunciation,category,definition,examples,stt_priority,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET term=excluded.term,aliases_json=excluded.aliases_json,pronunciation=excluded.pronunciation,category=excluded.category,definition=excluded.definition,examples=excluded.examples,stt_priority=excluded.stt_priority,enabled=excluded.enabled,updated_at=excluded.updated_at""",values); conn.commit()
    audit_log("admin_jargon", summary=f"Jargon saved: {term}", details={"id":jid})
    return jsonify({"status":"saved","id":jid})


@app.get("/admin/api/knowledge")
@admin_api_required
def admin_knowledge():
    with session_db() as conn: rows=conn.execute("SELECT * FROM config_knowledge ORDER BY category,title").fetchall()
    return jsonify({"knowledge":[dict(r)|{"enabled":bool(r["enabled"])} for r in rows]})


@app.post("/admin/api/knowledge")
@admin_mutation_required
def admin_save_knowledge():
    body=request.get_json(silent=True) or {}; title=str(body.get("title") or "").strip(); content=str(body.get("content") or "").strip()
    if not title or not content: return jsonify({"error":"title_and_content_required"}),400
    raw_kid = str(body.get("id") or "").strip()
    if raw_kid and not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", raw_kid):
        return jsonify({"error":"invalid_knowledge_id"}),400
    kid=(raw_kid or re.sub(r"[^a-z0-9]+","_",title.lower()).strip("_") or ("k_"+uuid.uuid4().hex[:8]))[:80]; now=utc_now_iso()
    with session_db() as conn:
        conn.execute("""INSERT INTO config_knowledge(id,title,category,content,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET title=excluded.title,category=excluded.category,content=excluded.content,enabled=excluded.enabled,updated_at=excluded.updated_at""",
            (kid,title,str(body.get("category") or "")[:100],content[:12000],int(bool(body.get("enabled",True))),now,now)); conn.commit()
    audit_log("admin_knowledge", summary=f"Knowledge saved: {title}", details={"id":kid})
    return jsonify({"status":"saved","id":kid})


@app.post("/admin/api/salesforce-test")
@admin_mutation_required
def admin_salesforce_test():
    with session_db() as conn:
        row=conn.execute("SELECT salesforce_username FROM sessions WHERE salesforce_username IS NOT NULL ORDER BY updated_at DESC LIMIT 1").fetchone()
        if not row: row=conn.execute("SELECT salesforce_username FROM audit_events WHERE salesforce_username IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    if not row: return jsonify({"error":"no_known_salesforce_user"}),400
    username=row["salesforce_username"]
    try:
        sf=get_salesforce_access_token(username)
        data=salesforce_query(sf["access_token"],sf["instance_url"],f"SELECT Id,Name,Username FROM User WHERE Username='{soql_escape(username)}' LIMIT 1")
        return jsonify({"ok":True,"username":username,"instance_url":sf["instance_url"],"records":len(data.get("records",[])),"api_version":SF_API_VERSION})
    except Exception as exc:
        return jsonify({"ok":False,"error":str(exc)}),400


# ============================================================
# LOCAL DEV
# ============================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
    )
