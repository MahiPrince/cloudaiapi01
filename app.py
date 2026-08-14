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
# ENVIRONMENT CONFIGURATION
# ============================================================

# Microsoft Entra
ENTRA_TENANT_ID = os.environ["ENTRA_TENANT_ID"]
ENTRA_API_CLIENT_ID = os.environ["ENTRA_API_CLIENT_ID"]

# Salesforce
SF_CLIENT_ID = os.environ["SF_CLIENT_ID"]

SF_LOGIN_URL = (
    os.environ["SF_LOGIN_URL"]
    .rstrip("/")
)

SF_JWT_PRIVATE_KEY = (
    os.environ["SF_JWT_PRIVATE_KEY"]
    .replace("\\n", "\n")
)

# Keep the exact audience from our previously working JWT flow.
SF_JWT_AUDIENCE = "https://login.salesforce.com"

# Can be overridden later without changing code.
SF_API_VERSION = os.environ.get(
    "SF_API_VERSION",
    "67.0"
)

# OpenAI
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]


# ============================================================
# OPENAI CLIENT
# ============================================================

openai_client = OpenAI(
    api_key=OPENAI_API_KEY
)


# ============================================================
# MICROSOFT ENTRA CONFIG
# ============================================================

ENTRA_ISSUER = (
    f"https://login.microsoftonline.com/"
    f"{ENTRA_TENANT_ID}/v2.0"
)

ENTRA_JWKS_URL = (
    f"https://login.microsoftonline.com/"
    f"{ENTRA_TENANT_ID}/discovery/v2.0/keys"
)

entra_jwks_client = PyJWKClient(
    ENTRA_JWKS_URL
)


# ============================================================
# ENTRA ACCESS TOKEN VERIFICATION
# ============================================================

def verify_entra_access_token(token):

    signing_key = (
        entra_jwks_client
        .get_signing_key_from_jwt(token)
    )

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=ENTRA_API_CLIENT_ID,
        issuer=ENTRA_ISSUER,
    )

    scopes = (
        claims
        .get("scp", "")
        .split()
    )

    if "access_as_user" not in scopes:
        raise Exception(
            "Required scope access_as_user is missing."
        )

    return claims


def require_auth(route_function):

    @wraps(route_function)
    def wrapper(*args, **kwargs):

        auth_header = (
            request.headers
            .get("Authorization", "")
        )

        if not auth_header.startswith("Bearer "):

            return jsonify({
                "error": "missing_bearer_token"
            }), 401

        token = auth_header.split(
            " ",
            1
        )[1]

        try:

            claims = verify_entra_access_token(
                token
            )

        except Exception as e:

            return jsonify({
                "error": "invalid_token",
                "details": str(e)
            }), 401

        request.user_claims = claims

        return route_function(
            *args,
            **kwargs
        )

    return wrapper


# ============================================================
# SALESFORCE JWT BEARER AUTH
# ============================================================

def get_salesforce_access_token(
    salesforce_username
):

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
        algorithm="RS256"
    )

    token_url = (
        f"{SF_LOGIN_URL}"
        f"/services/oauth2/token"
    )

    response = requests.post(
        token_url,
        data={
            "grant_type":
                "urn:ietf:params:oauth:"
                "grant-type:jwt-bearer",

            "assertion":
                assertion,
        },
        timeout=30,
    )

    if not response.ok:

        raise Exception(
            "Salesforce authentication failed: "
            f"{response.status_code} "
            f"{response.text}"
        )

    data = response.json()

    return {
        "access_token":
            data["access_token"],

        "instance_url":
            data["instance_url"],
    }


# ============================================================
# GENERIC SALESFORCE QUERY
# ============================================================

def salesforce_query(
    access_token,
    instance_url,
    soql
):

    url = (
        f"{instance_url}"
        f"/services/data/"
        f"v{SF_API_VERSION}/query"
    )

    response = requests.get(
        url,
        headers={
            "Authorization":
                f"Bearer {access_token}"
        },
        params={
            "q": soql
        },
        timeout=30,
    )

    if not response.ok:

        raise Exception(
            "Salesforce query failed: "
            f"{response.status_code} "
            f"{response.text}"
        )

    return response.json()


# ============================================================
# SAFE SOQL HELPERS
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

    date.fromisoformat(value)

    return value


def clamp_limit(
    value,
    default=25,
    maximum=100
):

    try:
        value = int(value)

    except Exception:
        return default

    return max(
        1,
        min(
            value,
            maximum
        )
    )


# ============================================================
# CRM FORMATTERS
# ============================================================

def format_account(account):

    if not account:
        return None

    return {

        "id":
            account.get("Id"),

        "name":
            account.get("Name"),

        "industry":
            account.get("Industry"),

        "website":
            account.get("Website"),

        "phone":
            account.get("Phone"),


        # ----------------------------------------------------
        # CUSTOMER / BILLING ADDRESS
        # ----------------------------------------------------

        "billing_address": {

            "street":
                account.get(
                    "BillingStreet"
                ),

            "city":
                account.get(
                    "BillingCity"
                ),

            "state":
                account.get(
                    "BillingState"
                ),

            "postal_code":
                account.get(
                    "BillingPostalCode"
                ),

            "country":
                account.get(
                    "BillingCountry"
                ),

            "latitude":
                account.get(
                    "BillingLatitude"
                ),

            "longitude":
                account.get(
                    "BillingLongitude"
                ),
        },


        # ----------------------------------------------------
        # SHIPPING / SITE ADDRESS
        # ----------------------------------------------------

        "shipping_address": {

            "street":
                account.get(
                    "ShippingStreet"
                ),

            "city":
                account.get(
                    "ShippingCity"
                ),

            "state":
                account.get(
                    "ShippingState"
                ),

            "postal_code":
                account.get(
                    "ShippingPostalCode"
                ),

            "country":
                account.get(
                    "ShippingCountry"
                ),

            "latitude":
                account.get(
                    "ShippingLatitude"
                ),

            "longitude":
                account.get(
                    "ShippingLongitude"
                ),
        },
    }


def format_contact(contact):

    if not contact:
        return None

    return {

        "id":
            contact.get("Id"),

        "first_name":
            contact.get("FirstName"),

        "last_name":
            contact.get("LastName"),

        "name":
            contact.get("Name"),

        "title":
            contact.get("Title"),

        "department":
            contact.get("Department"),

        "email":
            contact.get("Email"),

        "phone":
            contact.get("Phone"),

        "mobile":
            contact.get("MobilePhone"),

        "account_id":
            contact.get("AccountId"),


        # ----------------------------------------------------
        # CONTACT MAILING ADDRESS
        # ----------------------------------------------------

        "mailing_address": {

            "street":
                contact.get(
                    "MailingStreet"
                ),

            "city":
                contact.get(
                    "MailingCity"
                ),

            "state":
                contact.get(
                    "MailingState"
                ),

            "postal_code":
                contact.get(
                    "MailingPostalCode"
                ),

            "country":
                contact.get(
                    "MailingCountry"
                ),

            "latitude":
                contact.get(
                    "MailingLatitude"
                ),

            "longitude":
                contact.get(
                    "MailingLongitude"
                ),
        },


        # Customer attached to contact
        "account":
            format_account(
                contact.get("Account")
            ),
    }


# ============================================================
# CRM TOOL:
# SEARCH OPPORTUNITIES
# ============================================================

def tool_search_opportunities(
    sf,
    salesforce_username,
    args
):

    username = soql_escape(
        salesforce_username
    )

    status = args.get(
        "status",
        "all"
    )

    limit = clamp_limit(
        args.get("limit"),
        default=25
    )

    include_contacts = bool(
        args.get("include_contacts")
    )


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
        "IsClosed",
        "IsWon",
        "AccountId",

        # Account/customer
        "Account.Id",
        "Account.Name",
        "Account.Industry",
        "Account.Website",
        "Account.Phone",

        # Billing/customer address
        "Account.BillingStreet",
        "Account.BillingCity",
        "Account.BillingState",
        "Account.BillingPostalCode",
        "Account.BillingCountry",
        "Account.BillingLatitude",
        "Account.BillingLongitude",

        # Shipping/site address
        "Account.ShippingStreet",
        "Account.ShippingCity",
        "Account.ShippingState",
        "Account.ShippingPostalCode",
        "Account.ShippingCountry",
        "Account.ShippingLatitude",
        "Account.ShippingLongitude",
    ]


    # --------------------------------------------------------
    # OPPORTUNITY CONTACT ROLES
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # ALWAYS SCOPE OPPORTUNITIES TO AUTHENTICATED USER
    # --------------------------------------------------------

    where = [
        f"Owner.Username = '{username}'"
    ]


    # --------------------------------------------------------
    # STATUS FILTER
    # --------------------------------------------------------

    if status == "open":

        where.append(
            "IsClosed = false"
        )

    elif status == "closed_won":

        where.append(
            "IsWon = true"
        )

    elif status == "closed_lost":

        where.append(
            "IsClosed = true "
            "AND IsWon = false"
        )


    # --------------------------------------------------------
    # NAME FILTER
    # --------------------------------------------------------

    if args.get("name_contains"):

        value = soql_like_escape(
            args["name_contains"]
        )

        where.append(
            f"Name LIKE '%{value}%'"
        )


    # --------------------------------------------------------
    # ACCOUNT NAME
    # --------------------------------------------------------

    if args.get(
        "account_name_contains"
    ):

        value = soql_like_escape(
            args[
                "account_name_contains"
            ]
        )

        where.append(
            f"Account.Name "
            f"LIKE '%{value}%'"
        )


    # --------------------------------------------------------
    # STAGE
    # --------------------------------------------------------

    if args.get("stage"):

        value = soql_escape(
            args["stage"]
        )

        where.append(
            f"StageName = '{value}'"
        )


    # --------------------------------------------------------
    # AMOUNT
    # --------------------------------------------------------

    if (
        args.get("min_amount")
        is not None
    ):

        min_amount = float(
            args["min_amount"]
        )

        where.append(
            f"Amount >= {min_amount}"
        )


    if (
        args.get("max_amount")
        is not None
    ):

        max_amount = float(
            args["max_amount"]
        )

        where.append(
            f"Amount <= {max_amount}"
        )


    # --------------------------------------------------------
    # CLOSE DATE
    # --------------------------------------------------------

    if args.get(
        "close_date_from"
    ):

        value = validate_iso_date(
            args["close_date_from"]
        )

        where.append(
            f"CloseDate >= {value}"
        )


    if args.get(
        "close_date_to"
    ):

        value = validate_iso_date(
            args["close_date_to"]
        )

        where.append(
            f"CloseDate <= {value}"
        )


    # --------------------------------------------------------
    # CUSTOMER LOCATION
    # --------------------------------------------------------

    if args.get("account_state"):

        value = soql_escape(
            args["account_state"]
        )

        where.append(
            f"Account.BillingState "
            f"= '{value}'"
        )


    if args.get(
        "account_country"
    ):

        value = soql_escape(
            args["account_country"]
        )

        where.append(
            f"Account.BillingCountry "
            f"= '{value}'"
        )


    # --------------------------------------------------------
    # BUILD QUERY
    # --------------------------------------------------------

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
        soql
    )


    opportunities = []


    # --------------------------------------------------------
    # FORMAT RESULTS
    # --------------------------------------------------------

    for row in data.get(
        "records",
        []
    ):

        contacts = []


        if include_contacts:

            contact_roles = (
                row.get(
                    "OpportunityContactRoles"
                )
                or {}
            )

            for role in contact_roles.get(
                "records",
                []
            ):

                contacts.append({

                    "role":
                        role.get("Role"),

                    "is_primary":
                        role.get(
                            "IsPrimary"
                        ),

                    "contact":
                        format_contact(
                            role.get(
                                "Contact"
                            )
                        ),
                })


        opportunities.append({

            "id":
                row.get("Id"),

            "name":
                row.get("Name"),

            "stage":
                row.get(
                    "StageName"
                ),

            "amount":
                row.get("Amount"),

            "close_date":
                row.get(
                    "CloseDate"
                ),

            "probability":
                row.get(
                    "Probability"
                ),

            "next_step":
                row.get(
                    "NextStep"
                ),

            "type":
                row.get("Type"),

            "lead_source":
                row.get(
                    "LeadSource"
                ),

            "forecast_category":
                row.get(
                    "ForecastCategoryName"
                ),

            "is_closed":
                row.get(
                    "IsClosed"
                ),

            "is_won":
                row.get(
                    "IsWon"
                ),

            "account":
                format_account(
                    row.get("Account")
                ),

            "contacts":
                contacts,
        })


    return {

        "ok": True,

        "count":
            len(opportunities),

        "opportunities":
            opportunities,
    }


# ============================================================
# CRM TOOL:
# SEARCH CONTACTS
# ============================================================

def tool_search_contacts(
    sf,
    salesforce_username,
    args
):

    username = soql_escape(
        salesforce_username
    )

    limit = clamp_limit(
        args.get("limit"),
        default=25
    )


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

        # Contact mailing address
        "MailingStreet",
        "MailingCity",
        "MailingState",
        "MailingPostalCode",
        "MailingCountry",
        "MailingLatitude",
        "MailingLongitude",

        # Customer
        "Account.Id",
        "Account.Name",
        "Account.Industry",
        "Account.Website",
        "Account.Phone",

        # Customer billing address
        "Account.BillingStreet",
        "Account.BillingCity",
        "Account.BillingState",
        "Account.BillingPostalCode",
        "Account.BillingCountry",
        "Account.BillingLatitude",
        "Account.BillingLongitude",

        # Customer shipping/site address
        "Account.ShippingStreet",
        "Account.ShippingCity",
        "Account.ShippingState",
        "Account.ShippingPostalCode",
        "Account.ShippingCountry",
        "Account.ShippingLatitude",
        "Account.ShippingLongitude",
    ]


    # --------------------------------------------------------
    # ONLY CONTACTS FROM ACCOUNTS THAT HAVE USER'S OPPS
    # --------------------------------------------------------

    where = [

        (
            "AccountId IN "
            "("
                "SELECT AccountId "
                "FROM Opportunity "
                "WHERE Owner.Username "
                f"= '{username}'"
            ")"
        )
    ]


    # --------------------------------------------------------
    # CONTACT NAME
    # --------------------------------------------------------

    if args.get("name_contains"):

        value = soql_like_escape(
            args["name_contains"]
        )

        where.append(
            f"Name LIKE '%{value}%'"
        )


    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    if args.get(
        "title_contains"
    ):

        value = soql_like_escape(
            args["title_contains"]
        )

        where.append(
            f"Title LIKE '%{value}%'"
        )


    # --------------------------------------------------------
    # CUSTOMER NAME
    # --------------------------------------------------------

    if args.get(
        "account_name_contains"
    ):

        value = soql_like_escape(
            args[
                "account_name_contains"
            ]
        )

        where.append(
            f"Account.Name "
            f"LIKE '%{value}%'"
        )


    # --------------------------------------------------------
    # CUSTOMER STATE
    # --------------------------------------------------------

    if args.get(
        "account_state"
    ):

        value = soql_escape(
            args["account_state"]
        )

        where.append(
            f"Account.BillingState "
            f"= '{value}'"
        )


    # --------------------------------------------------------
    # CUSTOMER COUNTRY
    # --------------------------------------------------------

    if args.get(
        "account_country"
    ):

        value = soql_escape(
            args["account_country"]
        )

        where.append(
            f"Account.BillingCountry "
            f"= '{value}'"
        )


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
        soql
    )


    contacts = [

        format_contact(row)

        for row in data.get(
            "records",
            []
        )
    ]


    return {

        "ok": True,

        "count":
            len(contacts),

        "contacts":
            contacts,
    }


# ============================================================
# CRM TOOL:
# SEARCH ACCOUNTS / CUSTOMERS
# ============================================================

def tool_search_accounts(
    sf,
    salesforce_username,
    args
):

    username = soql_escape(
        salesforce_username
    )

    limit = clamp_limit(
        args.get("limit"),
        default=25
    )


    fields = [

        "Id",
        "Name",
        "Industry",
        "Website",
        "Phone",

        # Billing/customer address
        "BillingStreet",
        "BillingCity",
        "BillingState",
        "BillingPostalCode",
        "BillingCountry",
        "BillingLatitude",
        "BillingLongitude",

        # Shipping/site address
        "ShippingStreet",
        "ShippingCity",
        "ShippingState",
        "ShippingPostalCode",
        "ShippingCountry",
        "ShippingLatitude",
        "ShippingLongitude",
    ]


    # --------------------------------------------------------
    # ONLY CUSTOMER ACCOUNTS RELATED TO USER'S OPPORTUNITIES
    # --------------------------------------------------------

    where = [

        (
            "Id IN "
            "("
                "SELECT AccountId "
                "FROM Opportunity "
                "WHERE Owner.Username "
                f"= '{username}'"
            ")"
        )
    ]


    # --------------------------------------------------------
    # NAME
    # --------------------------------------------------------

    if args.get(
        "name_contains"
    ):

        value = soql_like_escape(
            args["name_contains"]
        )

        where.append(
            f"Name LIKE '%{value}%'"
        )


    # --------------------------------------------------------
    # INDUSTRY
    # --------------------------------------------------------

    if args.get(
        "industry_contains"
    ):

        value = soql_like_escape(
            args[
                "industry_contains"
            ]
        )

        where.append(
            f"Industry LIKE '%{value}%'"
        )


    # --------------------------------------------------------
    # CITY
    # --------------------------------------------------------

    if args.get("city"):

        value = soql_escape(
            args["city"]
        )

        where.append(
            f"BillingCity = '{value}'"
        )


    # --------------------------------------------------------
    # STATE
    # --------------------------------------------------------

    if args.get("state"):

        value = soql_escape(
            args["state"]
        )

        where.append(
            f"BillingState = '{value}'"
        )


    # --------------------------------------------------------
    # COUNTRY
    # --------------------------------------------------------

    if args.get("country"):

        value = soql_escape(
            args["country"]
        )

        where.append(
            f"BillingCountry = '{value}'"
        )


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
        soql
    )


    accounts = [

        format_account(row)

        for row in data.get(
            "records",
            []
        )
    ]


    return {

        "ok": True,

        "count":
            len(accounts),

        "accounts":
            accounts,
    }


# ============================================================
# OPENAI CRM TOOL DEFINITIONS
# ============================================================

CRM_READ_TOOLS = [

    # ========================================================
    # OPPORTUNITY SEARCH
    # ========================================================

    {
        "type": "function",

        "name":
            "search_opportunities",

        "description":
            (
                "Search the authenticated user's Salesforce "
                "opportunities. Returns opportunity details, "
                "customer/account information including "
                "billing and shipping addresses, and optionally "
                "contacts associated through Opportunity "
                "Contact Roles."
            ),

        "strict": True,

        "parameters": {

            "type": "object",

            "properties": {

                "name_contains": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "account_name_contains": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "status": {

                    "type":
                        "string",

                    "enum": [
                        "all",
                        "open",
                        "closed_won",
                        "closed_lost"
                    ]
                },

                "stage": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "min_amount": {
                    "type": [
                        "number",
                        "null"
                    ]
                },

                "max_amount": {
                    "type": [
                        "number",
                        "null"
                    ]
                },

                "close_date_from": {

                    "type": [
                        "string",
                        "null"
                    ],

                    "description":
                        "ISO date YYYY-MM-DD."
                },

                "close_date_to": {

                    "type": [
                        "string",
                        "null"
                    ],

                    "description":
                        "ISO date YYYY-MM-DD."
                },

                "account_state": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "account_country": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "include_contacts": {
                    "type":
                        "boolean"
                },

                "limit": {

                    "type":
                        "integer",

                    "minimum":
                        1,

                    "maximum":
                        100
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
                "account_state",
                "account_country",
                "include_contacts",
                "limit"
            ],

            "additionalProperties":
                False,
        },
    },


    # ========================================================
    # CONTACT SEARCH
    # ========================================================

    {
        "type":
            "function",

        "name":
            "search_contacts",

        "description":
            (
                "Search contacts belonging to customer "
                "accounts connected to opportunities owned "
                "by the authenticated Salesforce user. "
                "Returns contact name, title, department, "
                "email, phone, mobile number, mailing "
                "address and customer/account information."
            ),

        "strict":
            True,

        "parameters": {

            "type":
                "object",

            "properties": {

                "name_contains": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "title_contains": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "account_name_contains": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "account_state": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "account_country": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "limit": {

                    "type":
                        "integer",

                    "minimum":
                        1,

                    "maximum":
                        100
                },
            },

            "required": [

                "name_contains",
                "title_contains",
                "account_name_contains",
                "account_state",
                "account_country",
                "limit"
            ],

            "additionalProperties":
                False,
        },
    },


    # ========================================================
    # ACCOUNT / CUSTOMER SEARCH
    # ========================================================

    {
        "type":
            "function",

        "name":
            "search_accounts",

        "description":
            (
                "Search customer accounts associated with "
                "opportunities owned by the authenticated "
                "Salesforce user. Returns customer name, "
                "industry, website, phone, billing address, "
                "shipping/site address and coordinates "
                "when populated in Salesforce."
            ),

        "strict":
            True,

        "parameters": {

            "type":
                "object",

            "properties": {

                "name_contains": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "industry_contains": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "city": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "state": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "country": {
                    "type": [
                        "string",
                        "null"
                    ]
                },

                "limit": {

                    "type":
                        "integer",

                    "minimum":
                        1,

                    "maximum":
                        100
                },
            },

            "required": [

                "name_contains",
                "industry_contains",
                "city",
                "state",
                "country",
                "limit"
            ],

            "additionalProperties":
                False,
        },
    },
]


# ============================================================
# CRM TOOL DISPATCHER
# ============================================================

def run_crm_tool(
    tool_name,
    arguments,
    sf,
    salesforce_username
):

    try:

        if (
            tool_name
            == "search_opportunities"
        ):

            return tool_search_opportunities(
                sf,
                salesforce_username,
                arguments
            )


        if (
            tool_name
            == "search_contacts"
        ):

            return tool_search_contacts(
                sf,
                salesforce_username,
                arguments
            )


        if (
            tool_name
            == "search_accounts"
        ):

            return tool_search_accounts(
                sf,
                salesforce_username,
                arguments
            )


        return {
            "ok": False,
            "error":
                f"Unknown CRM tool: "
                f"{tool_name}"
        }


    except Exception as e:

        return {
            "ok": False,
            "error": str(e)
        }


# ============================================================
# AI ROUTER STRUCTURED OUTPUT
# ============================================================

class RouteDecision(BaseModel):

    action: Literal[
        "answer",
        "reroute"
    ]

    route: Literal[
        "simple",
        "crm_read",
        "crm_analysis",
        "web_simple",
        "web_research",
        "workflow",
        "deep_complex"
    ]

    target_model: Literal[
        "gpt-5.6-luna",
        "gpt-5.6-terra",
        "gpt-5.6-sol"
    ]

    reasoning_effort: Literal[
        "low",
        "medium",
        "high",
        "xhigh",
        "max"
    ]

    needs_salesforce: bool

    needs_web: bool

    needs_write: bool

    requires_confirmation: bool

    routing_note: str

    answer: Optional[str]


# ============================================================
# ROUTER INSTRUCTIONS
# ============================================================

ROUTER_INSTRUCTIONS = """
You are the intelligent routing layer for an enterprise
sales CRM AI assistant.

You receive one user request.

You must either:

1. Answer it directly when it is genuinely simple and needs
   no private CRM data, live information, tools or substantial
   analysis.

OR

2. Route it to the appropriate execution tier.


============================================================
SIMPLE
============================================================

Use when the question can be answered from general knowledge.

No Salesforce.
No web.
No user-specific private data.
No workflow.

Examples:

"What is a Salesforce opportunity?"
"What does pipeline mean?"

Use:

action = answer
route = simple
target_model = gpt-5.6-luna
reasoning_effort = low

Return the useful answer in the answer field.


============================================================
CRM_READ
============================================================

Use when Salesforce data is required but the operation is
primarily retrieval, filtering, counting or straightforward
summarization.

This includes:

- Opportunities
- Accounts
- Customers
- Customer addresses
- Contacts
- Contact details
- Contact roles
- Opportunity amounts
- Close dates
- Stages
- Customer locations

Examples:

"List all my opportunities."

"Show me customers in California."

"Who are my contacts at United Oil?"

"What is the address of this customer?"

Use:

action = reroute
route = crm_read
target_model = gpt-5.6-luna
reasoning_effort = low
needs_salesforce = true


============================================================
CRM_ANALYSIS
============================================================

Use when Salesforce data is needed AND the user wants:

- comparison
- prioritization
- risk assessment
- interpretation
- recommendations
- strategic analysis

Examples:

"Which three opportunities look most at risk?"

"Which accounts should I prioritize?"

"Analyze my pipeline."

Use:

action = reroute
route = crm_analysis
target_model = gpt-5.6-terra
reasoning_effort = medium or high
needs_salesforce = true


============================================================
WEB_SIMPLE
============================================================

Use when current public information is required but the task
is straightforward.

Examples:

"Who is the current CEO of Agilent?"

"Did Thermo Fisher announce anything today?"

Use:

action = reroute
route = web_simple
target_model = gpt-5.6-terra
reasoning_effort = medium
needs_web = true


============================================================
WEB_RESEARCH
============================================================

Use when multiple searches, sources or comparisons are
required.

Also use this when Salesforce and current web information
must be synthesized.

Examples:

"Research recent United Oil developments and compare them
with my open opportunities."

"Research Agilent and Waters and tell me how their activity
affects my pipeline."

Use:

action = reroute
route = web_research
target_model = gpt-5.6-terra
reasoning_effort = high
needs_web = true

Set needs_salesforce true when CRM data is also necessary.


============================================================
WORKFLOW
============================================================

Use for multi-step actions or state-changing tasks.

Examples:

"Research my largest accounts, make a follow-up plan and
update every opportunity."

"Find customers I should contact and create follow-up tasks."

Use:

action = reroute
route = workflow
target_model = gpt-5.6-terra
reasoning_effort = high

Set needs_write = true whenever external data would be changed.

Set requires_confirmation = true for:

- Salesforce writes
- bulk changes
- deletions
- sending communications
- other consequential actions


============================================================
DEEP_COMPLEX
============================================================

Use for unusually difficult, broad, high-value or
multi-source strategic reasoning.

Examples:

"Analyze my entire win/loss history, research every potential
customer in my territory and identify the strongest new leads."

"Build a full commercial strategy from CRM history,
competitor activity, market changes and customer signals."

Use:

action = reroute
route = deep_complex
target_model = gpt-5.6-sol
reasoning_effort = high, xhigh or max


============================================================
CRITICAL RULES
============================================================

Never fabricate Salesforce information.

Never answer Salesforce-specific questions without actually
using Salesforce data.

Never pretend that web research was performed.

Never fabricate customer names, opportunity values, contact
details, addresses, emails or phone numbers.

If Salesforce is needed:
needs_salesforce = true.

If current public information is needed:
needs_web = true.

If both are required:
set both true.

If external state must change:
needs_write = true.

If the request requires consequential writes:
requires_confirmation = true.

Do not unnecessarily escalate simple requests.

But do not answer from assumptions when real CRM or live data
is required.

routing_note must be a short explanation of the selected
route. It must not contain private chain-of-thought.

When action = reroute:
answer must be null.

When action = answer:
answer must contain the final user-facing answer.
"""


# ============================================================
# ROUTER
# ============================================================

def route_or_answer(
    user_message
):

    response = (
        openai_client
        .responses
        .parse(
            model="gpt-5.6-luna",

            reasoning={
                "effort": "low"
            },

            store=False,

            input=[

                {
                    "role":
                        "developer",

                    "content":
                        ROUTER_INSTRUCTIONS,
                },

                {
                    "role":
                        "user",

                    "content":
                        user_message,
                },
            ],

            text_format=
                RouteDecision,
        )
    )


    decision = (
        response.output_parsed
    )


    if decision is None:

        raise Exception(
            "OpenAI router returned "
            "no structured decision."
        )


    return decision


# ============================================================
# CRM AGENT INSTRUCTIONS
# ============================================================

CRM_AGENT_INSTRUCTIONS = """
You are an enterprise sales CRM assistant.

The user is authenticated through Microsoft Entra.

The backend authenticates to Salesforce as the corresponding
Salesforce user.

You have read-only Salesforce tools.

Use a CRM tool whenever the user's request depends on CRM
data.

Do not answer CRM-specific questions from assumptions.

Never invent:

- opportunities
- customers
- contacts
- addresses
- amounts
- stages
- dates
- phone numbers
- emails
- titles
- Salesforce fields

If Salesforce returns null or missing data, explicitly say
that the information is not populated in Salesforce.

Account billing addresses represent the primary customer
billing/location information.

Account shipping addresses can represent shipping or site
information.

Contact mailing addresses are contact-level addresses.

Contacts associated with an Opportunity are represented
through Opportunity Contact Roles.

You may call multiple CRM tools if necessary.

For analysis, distinguish Salesforce facts from your own
interpretation.

When assessing opportunity risk, consider available facts
such as:

- stage
- amount
- close date
- probability
- next step
- forecast category
- missing contact information
- missing next step
- customer information

Do not invent a risk signal that Salesforce did not return.

You currently have READ-ONLY access.

There are no write tools.

Never claim that you modified Salesforce.
"""


# ============================================================
# CRM AGENT EXECUTION
# ============================================================

def execute_crm_agent(
    user_message,
    decision,
    sf,
    salesforce_username
):

    # --------------------------------------------------------
    # MODEL SAFETY FLOOR
    # --------------------------------------------------------

    if decision.route == "crm_read":

        model = (
            "gpt-5.6-luna"
        )

        effort = "low"


    elif decision.route == "crm_analysis":

        model = (
            "gpt-5.6-terra"
        )

        # Router can choose medium/high.
        # Keep at least medium for analysis.

        if (
            decision.reasoning_effort
            in {
                "high",
                "xhigh",
                "max"
            }
        ):

            effort = (
                decision
                .reasoning_effort
            )

        else:

            effort = "medium"


    else:

        raise Exception(
            "This route is not enabled "
            "for CRM execution."
        )


    # --------------------------------------------------------
    # CONVERSATION INPUT
    # --------------------------------------------------------

    input_items = [

        {
            "role":
                "developer",

            "content":
                (
                    CRM_AGENT_INSTRUCTIONS
                    + "\n\nCurrent date: "
                    + date.today().isoformat()
                ),
        },

        {
            "role":
                "user",

            "content":
                user_message,
        },
    ]


    tool_trace = []


    # --------------------------------------------------------
    # MULTI-ROUND TOOL LOOP
    # --------------------------------------------------------

    for round_number in range(
        1,
        7
    ):

        response = (
            openai_client
            .responses
            .create(

                model=model,

                reasoning={
                    "effort":
                        effort
                },

                tools=
                    CRM_READ_TOOLS,

                input=
                    input_items,

                store=False,
            )
        )


        # ----------------------------------------------------
        # IMPORTANT:
        #
        # Preserve model output for next tool round,
        # including reasoning/function-call items.
        # ----------------------------------------------------

        input_items += (
            response.output
        )


        function_calls = [

            item

            for item
            in response.output

            if (
                item.type
                == "function_call"
            )
        ]


        # ----------------------------------------------------
        # NO FUNCTIONS = MODEL IS FINISHED
        # ----------------------------------------------------

        if not function_calls:

            answer = (
                response.output_text
                or ""
            ).strip()


            if not answer:

                answer = (
                    "I couldn't produce a "
                    "final answer from the "
                    "available CRM data."
                )


            return {

                "answer":
                    answer,

                "execution_model":
                    model,

                "reasoning_effort":
                    effort,

                "tool_rounds":
                    round_number - 1,

                "tool_trace":
                    tool_trace,
            }


        # ----------------------------------------------------
        # EXECUTE TOOL CALLS
        # ----------------------------------------------------

        for call in function_calls:

            try:

                arguments = (
                    json.loads(
                        call.arguments
                    )
                )

            except Exception as e:

                result = {
                    "ok": False,
                    "error":
                        (
                            "Invalid tool "
                            "arguments: "
                            + str(e)
                        )
                }

            else:

                result = run_crm_tool(

                    call.name,

                    arguments,

                    sf,

                    salesforce_username
                )


            # -----------------------------------------------
            # DEBUG TRACE
            # -----------------------------------------------

            tool_trace.append({

                "round":
                    round_number,

                "tool":
                    call.name,

                "arguments":
                    arguments
                    if "arguments"
                    in locals()
                    else None,

                "ok":
                    result.get(
                        "ok",
                        False
                    ),

                "result_count":
                    result.get(
                        "count"
                    ),
            })


            # -----------------------------------------------
            # SEND TOOL RESULT BACK TO OPENAI
            # -----------------------------------------------

            input_items.append({

                "type":
                    "function_call_output",

                "call_id":
                    call.call_id,

                "output":
                    json.dumps(
                        result,
                        default=str
                    ),
            })


    raise Exception(
        "CRM agent exceeded the "
        "maximum number of tool rounds."
    )


# ============================================================
# ROUTE:
# ROOT
# ============================================================

@app.get("/")
def root():

    return jsonify({

        "service":
            "CMD AI API",

        "status":
            "running",

        "version":
            "crm-agent-v1"
    })


# ============================================================
# ROUTE:
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return jsonify({
        "ok": True
    })


# ============================================================
# ROUTE:
# MICROSOFT IDENTITY
# ============================================================

@app.get("/me")
@require_auth
def me():

    claims = (
        request.user_claims
    )

    return jsonify({

        "authenticated":
            True,

        "name":
            claims.get("name"),

        "username":
            claims.get(
                "preferred_username"
            ),

        "oid":
            claims.get("oid"),

        "tenant_id":
            claims.get("tid"),

        "scope":
            claims.get("scp"),

        "audience":
            claims.get("aud"),

        "token_version":
            claims.get("ver"),
    })


# ============================================================
# ROUTE:
# SALESFORCE IDENTITY / CONNECTION TEST
# ============================================================

@app.get("/salesforce/me")
@require_auth
def salesforce_me():

    claims = (
        request.user_claims
    )

    entra_username = (
        claims.get(
            "preferred_username"
        )
    )


    if not entra_username:

        return jsonify({
            "error":
                "preferred_username_missing"
        }), 400


    # --------------------------------------------------------
    # CURRENT POC MAPPING:
    #
    # Entra preferred_username
    # ==
    # Salesforce Username
    #
    # Later replace this with tenant+oid mapping.
    # --------------------------------------------------------

    salesforce_username = (
        entra_username
    )


    try:

        sf = (
            get_salesforce_access_token(
                salesforce_username
            )
        )

    except Exception as e:

        return jsonify({

            "microsoft_authenticated":
                True,

            "salesforce_authenticated":
                False,

            "microsoft_username":
                entra_username,

            "salesforce_username":
                salesforce_username,

            "error":
                str(e),

        }), 502


    # --------------------------------------------------------
    # QUERY TEST
    # --------------------------------------------------------

    safe_username = (
        soql_escape(
            salesforce_username
        )
    )


    soql = f"""
        SELECT
            Id,
            Name,
            StageName,
            Amount,
            CloseDate
        FROM Opportunity
        WHERE Owner.Username = '{safe_username}'
        ORDER BY CloseDate ASC
        LIMIT 100
    """


    try:

        opportunity_data = (
            salesforce_query(

                sf[
                    "access_token"
                ],

                sf[
                    "instance_url"
                ],

                soql
            )
        )

    except Exception as e:

        # Important distinction:
        # Salesforce authentication itself worked,
        # but the user's license/permissions may block
        # Opportunity access — exactly what happened with Bob.

        return jsonify({

            "microsoft_authenticated":
                True,

            "salesforce_authenticated":
                True,

            "salesforce_query_success":
                False,

            "microsoft_username":
                entra_username,

            "salesforce_username":
                salesforce_username,

            "error":
                str(e),

        }), 403


    opportunities = []


    for row in opportunity_data.get(
        "records",
        []
    ):

        opportunities.append({

            "id":
                row.get("Id"),

            "name":
                row.get("Name"),

            "stage":
                row.get(
                    "StageName"
                ),

            "amount":
                row.get("Amount"),

            "close_date":
                row.get(
                    "CloseDate"
                ),
        })


    return jsonify({

        "microsoft": {

            "name":
                claims.get(
                    "name"
                ),

            "username":
                entra_username,

            "oid":
                claims.get(
                    "oid"
                ),

            "tenant_id":
                claims.get(
                    "tid"
                ),
        },

        "salesforce": {

            "connected":
                True,

            "username":
                salesforce_username,

            "instance":
                sf[
                    "instance_url"
                ],
        },

        "opportunity_count":
            len(
                opportunities
            ),

        "opportunities":
            opportunities,
    })


# ============================================================
# ROUTE:
# AI CHAT
# ============================================================

@app.post("/chat")
@require_auth
def chat():

    body = (
        request.get_json(
            silent=True
        )
        or {}
    )


    user_message = (
        body.get("message")
        or ""
    ).strip()


    if not user_message:

        return jsonify({
            "error":
                "message_required"
        }), 400


    claims = (
        request.user_claims
    )


    salesforce_username = (
        claims.get(
            "preferred_username"
        )
    )


    if not salesforce_username:

        return jsonify({
            "error":
                "preferred_username_missing"
        }), 400


    try:

        # ====================================================
        # STAGE 1:
        # LUNA LOW ROUTER
        # ====================================================

        decision = (
            route_or_answer(
                user_message
            )
        )


        route_data = (
            decision.model_dump()
        )


        # ====================================================
        # SIMPLE QUESTION
        #
        # Luna already produced the answer.
        # ====================================================

        if (
            decision.action
            == "answer"
        ):

            return jsonify({

                "status":
                    "answered",

                "user":
                    salesforce_username,

                "router_model":
                    "gpt-5.6-luna",

                "route":
                    route_data,

                "execution_model":
                    "gpt-5.6-luna",

                "answer":
                    decision.answer,

                "tool_trace":
                    [],
            })


        # ====================================================
        # CRM READ / CRM ANALYSIS
        # ====================================================

        if decision.route in {

            "crm_read",
            "crm_analysis"

        }:

            # -----------------------------------------------
            # Authenticate to Salesforce AS THIS USER
            # -----------------------------------------------

            sf = (
                get_salesforce_access_token(
                    salesforce_username
                )
            )


            # -----------------------------------------------
            # EXECUTE AGENT
            # -----------------------------------------------

            result = (
                execute_crm_agent(

                    user_message,

                    decision,

                    sf,

                    salesforce_username
                )
            )


            return jsonify({

                "status":
                    "answered",

                "user":
                    salesforce_username,

                "router_model":
                    "gpt-5.6-luna",

                "route":
                    route_data,

                "execution_model":
                    result[
                        "execution_model"
                    ],

                "execution_effort":
                    result[
                        "reasoning_effort"
                    ],

                "tool_rounds":
                    result[
                        "tool_rounds"
                    ],

                "tool_trace":
                    result[
                        "tool_trace"
                    ],

                "answer":
                    result[
                        "answer"
                    ],
            })


        # ====================================================
        # FUTURE ROUTES
        #
        # Router understands these but execution isn't
        # connected yet.
        # ====================================================

        return jsonify({

            "status":
                "routed",

            "user":
                salesforce_username,

            "router_model":
                "gpt-5.6-luna",

            "route":
                route_data,

            "message":
                (
                    "The router selected this "
                    "capability correctly, but "
                    "execution for this route "
                    "is not enabled yet."
                ),
        })


    except Exception as e:

        return jsonify({

            "error":
                "chat_failed",

            "details":
                str(e),

        }), 500


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
