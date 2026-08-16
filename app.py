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
from pathlib import Path
from datetime import date, datetime, timezone
from functools import wraps
from typing import Literal, Optional

import jwt
import requests
from flask import Flask, jsonify, request, send_file
from jwt import PyJWKClient
from openai import OpenAI
from pydantic import BaseModel, Field
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
SESSION_AUDIO_ROOT.mkdir(parents=True, exist_ok=True)


def session_db():
    conn = sqlite3.connect(str(SESSION_DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


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
        conn.commit()


init_session_db()


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def safe_session_id(value):
    raw = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,96}", raw):
        raise ValueError("Invalid session id.")
    return raw


def owner_session_row(session_id, owner_oid):
    with session_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ? AND owner_oid = ?",
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

    use_demo = bool(DEMO_GEO_ENABLED and (nearest_distance is None or nearest_distance > DEMO_GEO_REAL_RADIUS_KM))
    if use_demo:
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
        "demo_enabled": DEMO_GEO_ENABLED,
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
    username = soql_escape(salesforce_username)
    status = args.get("status", "all")
    limit = clamp_limit(args.get("limit"), default=25)
    include_contacts = bool(args.get("include_contacts"))

    fields = [
        "Id",
        "Name",
        "StageName",
        "Amount",
        "CloseDate",
        "Probability",
        "NextStep",
        "Type",
        "LeadSource",
        "ForecastCategoryName",
        "Description",
        "IsClosed",
        "IsWon",
        "AccountId",

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

    if include_contacts:
        fields.append(
            """
            (
                SELECT
                    Id,
                    ContactId,
                    Role,
                    IsPrimary,
                    Contact.Id,
                    Contact.FirstName,
                    Contact.LastName,
                    Contact.Name,
                    Contact.Title,
                    Contact.Department,
                    Contact.Email,
                    Contact.Phone,
                    Contact.MobilePhone,
                    Contact.MailingStreet,
                    Contact.MailingCity,
                    Contact.MailingState,
                    Contact.MailingPostalCode,
                    Contact.MailingCountry,
                    Contact.MailingLatitude,
                    Contact.MailingLongitude
                FROM OpportunityContactRoles
            )
            """
        )

    where = [f"Owner.Username = '{username}'"]

    if status == "open":
        where.append("IsClosed = false")
    elif status == "closed_won":
        where.append("IsWon = true")
    elif status == "closed_lost":
        where.append("IsClosed = true AND IsWon = false")

    if args.get("name_contains"):
        value = soql_like_escape(args["name_contains"])
        where.append(f"Name LIKE '%{value}%'")

    if args.get("account_name_contains"):
        value = soql_like_escape(args["account_name_contains"])
        where.append(f"Account.Name LIKE '%{value}%'")

    if args.get("stage"):
        value = soql_escape(args["stage"])
        where.append(f"StageName = '{value}'")

    if args.get("min_amount") is not None:
        where.append(f"Amount >= {float(args['min_amount'])}")

    if args.get("max_amount") is not None:
        where.append(f"Amount <= {float(args['max_amount'])}")

    if args.get("close_date_from"):
        value = validate_iso_date(args["close_date_from"])
        where.append(f"CloseDate >= {value}")

    if args.get("close_date_to"):
        value = validate_iso_date(args["close_date_to"])
        where.append(f"CloseDate <= {value}")

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
        + " FROM Opportunity "
        + "WHERE "
        + " AND ".join(where)
        + " ORDER BY CloseDate ASC "
        + f"LIMIT {limit}"
    )

    data = salesforce_query(
        sf["access_token"],
        sf["instance_url"],
        soql,
    )

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

        opportunities.append({
            "id": row.get("Id"),
            "name": row.get("Name"),
            "stage": row.get("StageName"),
            "amount": row.get("Amount"),
            "close_date": row.get("CloseDate"),
            "probability": row.get("Probability"),
            "next_step": row.get("NextStep"),
            "type": row.get("Type"),
            "lead_source": row.get("LeadSource"),
            "forecast_category": row.get("ForecastCategoryName"),
            "description": row.get("Description"),
            "is_closed": row.get("IsClosed"),
            "is_won": row.get("IsWon"),
            "account": format_account(row.get("Account")),
            "contacts": contacts,
        })

    return {
        "ok": True,
        "count": len(opportunities),
        "opportunities": opportunities,
    }


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

    # If we need to filter a polymorphic related-name in Python, fetch a slightly
    # larger safe window and then trim back to the requested limit.
    query_limit = min(100, max(limit, 75 if related_name else limit))

    fields = [
        "Id",
        "Subject",
        "StartDateTime",
        "EndDateTime",
        "ActivityDate",
        "IsAllDayEvent",
        "Location",
        "Description",
        "WhoId",
        "WhatId",
        "Who.Name",
        "What.Name",
        "OwnerId",
        "Owner.Name",
        "Owner.Username",
    ]

    where = [f"Owner.Username = '{username}'"]

    if args.get("start_datetime_from"):
        where.append(
            "StartDateTime >= " + salesforce_soql_datetime(args["start_datetime_from"])
        )

    if args.get("start_datetime_to"):
        where.append(
            "StartDateTime <= " + salesforce_soql_datetime(args["start_datetime_to"])
        )

    if args.get("subject_contains"):
        value = soql_like_escape(args["subject_contains"])
        where.append(f"Subject LIKE '%{value}%'")

    soql = (
        "SELECT "
        + ", ".join(fields)
        + " FROM Event WHERE "
        + " AND ".join(where)
        + " ORDER BY StartDateTime ASC "
        + f"LIMIT {query_limit}"
    )

    data = salesforce_query(sf["access_token"], sf["instance_url"], soql)
    events = [format_event(row) for row in data.get("records", [])]

    if related_name:
        events = [
            event for event in events
            if related_name in str((event.get("who") or {}).get("name") or "").lower()
            or related_name in str((event.get("what") or {}).get("name") or "").lower()
            or related_name in str(event.get("subject") or "").lower()
        ]

    events = events[:limit]

    return {
        "ok": True,
        "count": len(events),
        "events": events,
    }


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
            "Search the authenticated user's Salesforce opportunities. "
            "Returns opportunity details, customer/account information "
            "including billing and shipping addresses, and optionally "
            "contacts through Opportunity Contact Roles."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "name_contains": {"type": ["string", "null"]},
                "account_name_contains": {"type": ["string", "null"]},
                "status": {
                    "type": "string",
                    "enum": ["all", "open", "closed_won", "closed_lost"],
                },
                "stage": {"type": ["string", "null"]},
                "min_amount": {"type": ["number", "null"]},
                "max_amount": {"type": ["number", "null"]},
                "close_date_from": {
                    "type": ["string", "null"],
                    "description": "ISO date YYYY-MM-DD.",
                },
                "close_date_to": {
                    "type": ["string", "null"],
                    "description": "ISO date YYYY-MM-DD.",
                },
                "account_city": {"type": ["string", "null"]},
                "account_state": {"type": ["string", "null"]},
                "account_country": {"type": ["string", "null"]},
                "include_contacts": {"type": "boolean"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": [
                "name_contains",
                "account_name_contains",
                "status",
                "stage",
                "min_amount",
                "max_amount",
                "close_date_from",
                "close_date_to",
                "account_city",
                "account_state",
                "account_country",
                "include_contacts",
                "limit",
            ],
            "additionalProperties": False,
        },
    },

    {
        "type": "function",
        "name": "search_contacts",
        "description": (
            "Search contacts belonging to customer accounts connected "
            "to opportunities owned by the authenticated Salesforce user. "
            "Returns title, department, email, phone, mailing address, "
            "and associated customer/account information."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "name_contains": {"type": ["string", "null"]},
                "title_contains": {"type": ["string", "null"]},
                "account_name_contains": {"type": ["string", "null"]},
                "account_city": {"type": ["string", "null"]},
                "account_state": {"type": ["string", "null"]},
                "account_country": {"type": ["string", "null"]},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": [
                "name_contains",
                "title_contains",
                "account_name_contains",
                "account_city",
                "account_state",
                "account_country",
                "limit",
            ],
            "additionalProperties": False,
        },
    },

    {
        "type": "function",
        "name": "search_accounts",
        "description": (
            "Search customer accounts associated with opportunities "
            "owned by the authenticated Salesforce user. Returns customer "
            "name, industry, website, phone, billing address, shipping/site "
            "address, and coordinates when populated."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "name_contains": {"type": ["string", "null"]},
                "industry_contains": {"type": ["string", "null"]},
                "city": {"type": ["string", "null"]},
                "state": {"type": ["string", "null"]},
                "country": {"type": ["string", "null"]},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": [
                "name_contains",
                "industry_contains",
                "city",
                "state",
                "country",
                "limit",
            ],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "find_nearby_accounts",
        "description": (
            "Find customer Accounts with open opportunities near the user's effective current location. "
            "The backend performs deterministic distance calculations; do not invent geography. "
            "Use this for nearby customers, unplanned field visits, or a cancelled-meeting recovery workflow."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "radius_km": {"type": "number", "minimum": 1, "maximum": 300},
                "limit": {"type": "integer", "minimum": 1, "maximum": 25}
            },
            "required": ["radius_km", "limit"],
            "additionalProperties": False
        }
    },

    {
        "type": "function",
        "name": "search_events",
        "description": (
            "Search Salesforce Events owned by the authenticated user. Use this "
            "for meetings, appointments, scheduled customer visits, and calendar "
            "questions. Resolve relative dates using the supplied user device time."
        ),
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "start_datetime_from": {
                    "type": ["string", "null"],
                    "description": "ISO 8601 date-time with explicit timezone offset.",
                },
                "start_datetime_to": {
                    "type": ["string", "null"],
                    "description": "ISO 8601 date-time with explicit timezone offset.",
                },
                "subject_contains": {"type": ["string", "null"]},
                "related_name_contains": {
                    "type": ["string", "null"],
                    "description": "Contact, Account, Opportunity, or subject name fragment.",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": [
                "start_datetime_from",
                "start_datetime_to",
                "subject_contains",
                "related_name_contains",
                "limit",
            ],
            "additionalProperties": False,
        },
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

CAPABILITY_MANIFEST = {
    "salesforce": {
        "search_opportunities": True,
        "search_accounts": True,
        "search_contacts": True,
        "update_opportunities": True,
        "search_events": True,
        "create_events": True,
        "update_events": True,
        "create_tasks": False,
        "send_email": False,
    },
    "web_research": True,
    "location": {
        "foreground_gps": True,
        "demo_geography_adapter": True,
        "nearby_accounts": True
    },
    "sessions": {
        "iphone_recording": True,
        "background_recording": True,
        "diarized_transcription": True,
        "opportunity_linking": True,
        "voicepuck": "prototype_not_connected"
    },
}


def capability_prompt():
    return (
        "Available CMD Sally capabilities (authoritative):\n"
        + json.dumps(CAPABILITY_MANIFEST, indent=2)
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
- Salesforce retrieval/filtering/counting/straightforward summarization.
- Opportunities, accounts, customers, addresses, contacts, contact roles, Salesforce Events/meetings.
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
- Never invent CRM records or fields.
- Account billing/shipping addresses are customer/site address information.
- Contact mailing addresses are contact-level addresses.
- Opportunity contacts are represented by Opportunity Contact Roles.
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


def execute_agent(
    user_message,
    decision,
    sf,
    salesforce_username,
    claims,
    history=None,
    client_context=None,
    location_context=None,
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

        response = openai_client.responses.create(**kwargs)

        web_meta = collect_web_metadata(response)

        if web_meta["used"]:
            web_used = True

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
                    result = run_function_tool(
                        call.name,
                        arguments,
                        sf,
                        salesforce_username,
                        runtime_context={"location_context": location_context},
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
        chunk_text = str(payload.get("text") or "").strip()
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
                "text": str(segment.get("text") or "").strip(),
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
            {"role": "developer", "content": instructions},
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
# ROUTES
# ============================================================

@app.get("/")
def root():
    return jsonify({
        "service": "CMD Sally API",
        "status": "running",
        "version": "cmd-sally-v3",
    })


@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "version": "cmd-sally-v3",
        "session_storage_root": str(SESSION_STORAGE_ROOT),
        "persistent_disk_expected": str(SESSION_STORAGE_ROOT).startswith("/var/data"),
        "demo_geo_enabled": DEMO_GEO_ENABLED,
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


@app.post("/chat")
@require_auth
def chat():
    body = request.get_json(silent=True) or {}
    user_message = (body.get("message") or "").strip()
    history = normalize_conversation_history(body.get("history"))
    client_context = normalize_client_context(body.get("client_context"))

    if not user_message:
        return jsonify({"error": "message_required"}), 400

    claims = request.user_claims
    salesforce_username = claims.get("preferred_username")

    if not salesforce_username:
        return jsonify({
            "error": "preferred_username_missing"
        }), 400

    try:
        # Stage 1: cheap Luna router, with recent conversation context.
        decision = route_or_answer(
            user_message,
            history=history,
            client_context=client_context,
        )
        route_data = decision.model_dump()

        # Simple answer already completed by router.
        if decision.action == "answer":
            return jsonify({
                "status": "answered",
                "user": salesforce_username,
                "router_model": "gpt-5.6-luna",
                "route": route_data,
                "execution_model": "gpt-5.6-luna",
                "answer": decision.answer,
                "display_text": decision.answer,
                "speech_text": decision.answer,
                "conversation_text": decision.answer,
                "ui_blocks": [],
                "capabilities": CAPABILITY_MANIFEST,
                "tool_trace": [],
                "web_used": False,
                "web_sources": [],
                "pending_actions": [],
                "confirmation_required": False,
                "conversation_history_used": len(history),
            })

        sf = None

        if decision.needs_salesforce:
            sf = get_salesforce_access_token(
                salesforce_username
            )

        location_context = None
        if sf is not None and client_context.get("location"):
            location_context = resolve_location_context(
                sf, salesforce_username, client_context, claims
            )

        result = execute_agent(
            user_message,
            decision,
            sf,
            salesforce_username,
            claims,
            history=history,
            client_context=client_context,
            location_context=location_context,
        )

        response_body = {
            "status": (
                "confirmation_required"
                if result["confirmation_required"]
                else "answered"
            ),
            "user": salesforce_username,
            "router_model": "gpt-5.6-luna",
            "route": route_data,
            "execution_model": result["execution_model"],
            "execution_effort": result["reasoning_effort"],
            "tool_rounds": result["tool_rounds"],
            "tool_trace": result["tool_trace"],
            "web_used": result["web_used"],
            "web_search_trace": result["web_search_trace"],
            "web_sources": result["web_sources"],
            "pending_actions": result["pending_actions"],
            "confirmation_required": result["confirmation_required"],
            "answer": result["answer"],
            "display_text": result["display_text"],
            "speech_text": result["speech_text"],
            "conversation_text": result["conversation_text"],
            "ui_blocks": result["ui_blocks"],
            "capabilities": CAPABILITY_MANIFEST,
            "location_context": result.get("location_context"),
            "conversation_history_used": len(history),
        }

        if result["confirmation_token"]:
            response_body["confirmation_token"] = (
                result["confirmation_token"]
            )

        return jsonify(response_body)

    except Exception as e:
        return jsonify({
            "error": "chat_failed",
            "details": str(e),
        }), 500


@app.post("/location/resolve")
@require_auth
def resolve_device_location():
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
            "SELECT * FROM sessions WHERE owner_oid=? ORDER BY created_at DESC LIMIT 100",
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


# ============================================================
# LOCAL DEV
# ============================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
    )
