import os
import json
import time
from datetime import date
from functools import wraps
from typing import Literal, Optional

import jwt
import requests
from flask import Flask, jsonify, request
from jwt import PyJWKClient
from openai import OpenAI
from pydantic import BaseModel


# ============================================================
# APP
# ============================================================

app = Flask(__name__)


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

openai_client = OpenAI(api_key=OPENAI_API_KEY)


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
            "required": [
                "opportunity_id",
                "field_name",
                "new_value",
            ],
            "additionalProperties": False,
        },
    }
]


# ============================================================
# CRM FUNCTION DISPATCH
# ============================================================

def run_function_tool(
    tool_name,
    arguments,
    sf,
    salesforce_username,
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

        if tool_name == "propose_update_opportunity":
            return tool_propose_update_opportunity(
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
- Opportunities, accounts, customers, addresses, contacts, contact roles.
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
customer, deal, or prior CRM result from the conversation, normally route with
needs_salesforce=true so the current CRM state can be verified.
Conversation history is context, not proof that a CRM fact is still current.
Never pretend web research occurred.
If current information is required, needs_web=true.
If Salesforce data is required, needs_salesforce=true.
If Salesforce changes are requested, needs_write=true.
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
- Do not make the user repeat a customer, opportunity, contact, date, or choice
  that is already clear from the conversation.
- If a follow-up depends on CRM state, re-query Salesforce as needed rather than
  assuming an old value is still current.
- If more than one plausible referent remains, ask one concise clarification.
- Do not claim a tool/action exists merely because an earlier assistant message
  claimed it. The actual tools supplied to this request are authoritative.

Salesforce:
- The user is authenticated through Microsoft Entra.
- The backend authenticates to Salesforce as the corresponding Salesforce user.
- Use Salesforce tools whenever the request depends on CRM data.
- Never invent CRM records or fields.
- Account billing/shipping addresses are customer/site address information.
- Contact mailing addresses are contact-level addresses.
- Opportunity contacts are represented by Opportunity Contact Roles.
- Distinguish Salesforce facts from your interpretation.

Web:
- If this request was routed as needing web research, you MUST use web_search
  before giving the final answer.
- Prefer current, authoritative, first-party sources when available.
- Do not claim a current public fact without web support.
- Keep source attribution clear.

Writes:
- The only write-capable tool is propose_update_opportunity.
- It DOES NOT execute a write.
- It only creates a pending action.
- Never say Salesforce was updated until the backend confirmation endpoint
  reports success.
- If changes are pending, summarize exactly what would change and tell the
  user explicit confirmation is required.

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
        key = (
            action.get("opportunity_id"),
            action.get("field_name"),
            json.dumps(action.get("new_value"), sort_keys=True),
        )

        if key not in seen:
            seen.add(key)
            unique.append(action)

    return unique


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
                + client_time_prompt(client_context)
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

            answer = (response.output_text or "").strip()

            if not answer:
                raise Exception(
                    "Agent completed without a final text answer."
                )

            pending_actions = dedupe_pending_actions(pending_actions)

            confirmation_token = None

            if pending_actions:
                confirmation_token = create_confirmation_token(
                    claims,
                    salesforce_username,
                    pending_actions,
                )

            return {
                "answer": answer,
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
                    )

            if result.get("pending_action"):
                pending_actions.append(result["pending_action"])

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
        raise ValueError(
            "Confirmation token belongs to a different Entra user."
        )

    if token_payload.get("tid") != claims.get("tid"):
        raise ValueError(
            "Confirmation token belongs to a different Entra tenant."
        )

    salesforce_username = claims.get("preferred_username")

    if (
        not salesforce_username
        or token_payload.get("salesforce_username") != salesforce_username
    ):
        raise ValueError(
            "Confirmation token Salesforce identity does not match."
        )

    actions = token_payload.get("actions") or []

    if not actions:
        raise ValueError("No actions were found in the confirmation token.")

    sf = get_salesforce_access_token(salesforce_username)

    # First validate every action and check for stale data.
    validated = []

    for action in actions:
        if action.get("action") != "update_opportunity":
            raise ValueError("Unsupported confirmed action.")

        field_name = action.get("field_name")
        opportunity_id = action.get("opportunity_id")

        new_value = normalize_opportunity_write_value(
            field_name,
            action.get("new_value"),
        )

        current = get_owned_opportunity_field(
            sf,
            salesforce_username,
            opportunity_id,
            field_name,
        )

        if not values_equivalent(
            current["current_value"],
            action.get("old_value"),
        ):
            raise ValueError(
                f"Conflict: {current['name']} → {field_name} changed "
                "after the proposal was created. No writes were executed."
            )

        validated.append({
            "opportunity_id": current["id"],
            "opportunity_name": current["name"],
            "field_name": field_name,
            "old_value": current["current_value"],
            "new_value": new_value,
        })

    # PoC behavior: execute sequentially after all pre-checks pass.
    results = []

    for action in validated:
        salesforce_update_opportunity(
            sf["access_token"],
            sf["instance_url"],
            action["opportunity_id"],
            {
                action["field_name"]: action["new_value"]
            },
        )

        results.append({
            "opportunity_id": action["opportunity_id"],
            "opportunity_name": action["opportunity_name"],
            "field_name": action["field_name"],
            "old_value": action["old_value"],
            "new_value": action["new_value"],
            "status": "updated",
        })

    return results


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def root():
    return jsonify({
        "service": "CMD Sally API",
        "status": "running",
        "version": "conversational-v1",
    })


@app.get("/health")
def health():
    return jsonify({"ok": True})


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

        result = execute_agent(
            user_message,
            decision,
            sf,
            salesforce_username,
            claims,
            history=history,
            client_context=client_context,
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
