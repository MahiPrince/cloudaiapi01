import os
import time
from functools import wraps

import jwt
import requests
from jwt import PyJWKClient
from flask import Flask, jsonify, request
from typing import Literal, Optional

import json
from datetime import date
from openai import OpenAI
from pydantic import BaseModel


app = Flask(__name__)


# ============================================================
# MICROSOFT ENTRA CONFIG
# ============================================================

TENANT_ID = os.environ["ENTRA_TENANT_ID"]
API_CLIENT_ID = os.environ["ENTRA_API_CLIENT_ID"]

ENTRA_ISSUER = (
    f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
)

ENTRA_JWKS_URL = (
    f"https://login.microsoftonline.com/"
    f"{TENANT_ID}/discovery/v2.0/keys"
)

entra_jwks_client = PyJWKClient(ENTRA_JWKS_URL)


# ============================================================
# SALESFORCE CONFIG
# ============================================================

SF_CLIENT_ID = os.environ["SF_CLIENT_ID"]

SF_LOGIN_URL = (
    os.environ["SF_LOGIN_URL"].rstrip("/")
)

SF_JWT_AUDIENCE = os.environ.get(
    "SF_JWT_AUDIENCE",
    "https://login.salesforce.com"
)

SF_API_VERSION = "67.0"

openai_client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"]
)



def get_salesforce_private_key():
    """
    Load the RSA private key stored in Render.

    Also supports keys pasted with literal \\n characters.
    """

    key = os.environ["SF_JWT_PRIVATE_KEY"]

    key = key.replace("\\n", "\n")

    return key


# ============================================================
# CRM READ TOOLS
# ============================================================


def soql_escape(value):
    """
    Escape a normal SOQL string literal.
    """
    if value is None:
        return None

    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("'", "\\'")
    )


def soql_like_escape(value):
    """
    Escape text used inside LIKE '%...%'.
    """
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


def clamp_limit(value, default=25, maximum=100):
    try:
        value = int(value)
    except Exception:
        return default

    return max(
        1,
        min(value, maximum)
    )


# ============================================================
# CRM OUTPUT FORMATTERS
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

        "billing_address": {
            "street":
                account.get("BillingStreet"),

            "city":
                account.get("BillingCity"),

            "state":
                account.get("BillingState"),

            "postal_code":
                account.get("BillingPostalCode"),

            "country":
                account.get("BillingCountry"),

            "latitude":
                account.get("BillingLatitude"),

            "longitude":
                account.get("BillingLongitude"),
        },

        "shipping_address": {
            "street":
                account.get("ShippingStreet"),

            "city":
                account.get("ShippingCity"),

            "state":
                account.get("ShippingState"),

            "postal_code":
                account.get("ShippingPostalCode"),

            "country":
                account.get("ShippingCountry"),

            "latitude":
                account.get("ShippingLatitude"),

            "longitude":
                account.get("ShippingLongitude"),
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

        "mailing_address": {
            "street":
                contact.get("MailingStreet"),

            "city":
                contact.get("MailingCity"),

            "state":
                contact.get("MailingState"),

            "postal_code":
                contact.get("MailingPostalCode"),

            "country":
                contact.get("MailingCountry"),

            "latitude":
                contact.get("MailingLatitude"),

            "longitude":
                contact.get("MailingLongitude"),
        },

        "account":
            format_account(
                contact.get("Account")
            ),
    }


# ============================================================
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


    where = [
        f"Owner.Username = '{username}'"
    ]


    # --------------------------------------------------------
    # STATUS
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
            "IsClosed = true AND IsWon = false"
        )


    # --------------------------------------------------------
    # TEXT FILTERS
    # --------------------------------------------------------

    if args.get("name_contains"):

        value = soql_like_escape(
            args["name_contains"]
        )

        where.append(
            f"Name LIKE '%{value}%'"
        )


    if args.get("account_name_contains"):

        value = soql_like_escape(
            args["account_name_contains"]
        )

        where.append(
            f"Account.Name LIKE '%{value}%'"
        )


    if args.get("stage"):

        value = soql_escape(
            args["stage"]
        )

        where.append(
            f"StageName = '{value}'"
        )


    # --------------------------------------------------------
    # AMOUNT FILTERS
    # --------------------------------------------------------

    if args.get("min_amount") is not None:

        where.append(
            f"Amount >= {float(args['min_amount'])}"
        )


    if args.get("max_amount") is not None:

        where.append(
            f"Amount <= {float(args['max_amount'])}"
        )


    # --------------------------------------------------------
    # CLOSE DATE FILTERS
    # --------------------------------------------------------

    if args.get("close_date_from"):

        value = validate_iso_date(
            args["close_date_from"]
        )

        where.append(
            f"CloseDate >= {value}"
        )


    if args.get("close_date_to"):

        value = validate_iso_date(
            args["close_date_to"]
        )

        where.append(
            f"CloseDate <= {value}"
        )


    # --------------------------------------------------------
    # CUSTOMER LOCATION FILTERS
    # --------------------------------------------------------

    if args.get("account_state"):

        value = soql_escape(
            args["account_state"]
        )

        where.append(
            f"Account.BillingState = '{value}'"
        )


    if args.get("account_country"):

        value = soql_escape(
            args["account_country"]
        )

        where.append(
            f"Account.BillingCountry = '{value}'"
        )


    soql = (
        "SELECT "
        + ", ".join(fields)
        + " FROM Opportunity "
        + " WHERE "
        + " AND ".join(where)
        + " ORDER BY CloseDate ASC "
        + f" LIMIT {limit}"
    )


    data = salesforce_query(
        sf["access_token"],
        sf["instance_url"],
        soql
    )


    results = []


    for row in data.get(
        "records",
        []
    ):

        contacts = []


        if include_contacts:

            role_data = (
                row.get(
                    "OpportunityContactRoles"
                )
                or {}
            )

            for role in role_data.get(
                "records",
                []
            ):

                contacts.append({
                    "role":
                        role.get("Role"),

                    "is_primary":
                        role.get("IsPrimary"),

                    "contact":
                        format_contact(
                            role.get("Contact")
                        ),
                })


        results.append({

            "id":
                row.get("Id"),

            "name":
                row.get("Name"),

            "stage":
                row.get("StageName"),

            "amount":
                row.get("Amount"),

            "close_date":
                row.get("CloseDate"),

            "probability":
                row.get("Probability"),

            "next_step":
                row.get("NextStep"),

            "type":
                row.get("Type"),

            "lead_source":
                row.get("LeadSource"),

            "forecast_category":
                row.get(
                    "ForecastCategoryName"
                ),

            "is_closed":
                row.get("IsClosed"),

            "is_won":
                row.get("IsWon"),

            "account":
                format_account(
                    row.get("Account")
                ),

            "contacts":
                contacts,
        })


    return {
        "ok": True,
        "count": len(results),
        "opportunities": results,
    }


# ============================================================
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


    # Contacts belonging to customer accounts that have
    # Opportunities owned by this authenticated Salesforce user.

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

        value = soql_like_escape(
            args["name_contains"]
        )

        where.append(
            f"Name LIKE '%{value}%'"
        )


    if args.get("title_contains"):

        value = soql_like_escape(
            args["title_contains"]
        )

        where.append(
            f"Title LIKE '%{value}%'"
        )


    if args.get("account_name_contains"):

        value = soql_like_escape(
            args["account_name_contains"]
        )

        where.append(
            f"Account.Name LIKE '%{value}%'"
        )


    if args.get("account_state"):

        value = soql_escape(
            args["account_state"]
        )

        where.append(
            f"Account.BillingState = '{value}'"
        )


    if args.get("account_country"):

        value = soql_escape(
            args["account_country"]
        )

        where.append(
            f"Account.BillingCountry = '{value}'"
        )


    soql = (
        "SELECT "
        + ", ".join(fields)
        + " FROM Contact "
        + " WHERE "
        + " AND ".join(where)
        + " ORDER BY LastName ASC "
        + f" LIMIT {limit}"
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
        "count": len(contacts),
        "contacts": contacts,
    }


# ============================================================
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


    # Customer accounts connected to opportunities
    # owned by the authenticated user.

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

        value = soql_like_escape(
            args["name_contains"]
        )

        where.append(
            f"Name LIKE '%{value}%'"
        )


    if args.get("industry_contains"):

        value = soql_like_escape(
            args["industry_contains"]
        )

        where.append(
            f"Industry LIKE '%{value}%'"
        )


    if args.get("city"):

        value = soql_escape(
            args["city"]
        )

        where.append(
            f"BillingCity = '{value}'"
        )


    if args.get("state"):

        value = soql_escape(
            args["state"]
        )

        where.append(
            f"BillingState = '{value}'"
        )


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
        + " WHERE "
        + " AND ".join(where)
        + " ORDER BY Name ASC "
        + f" LIMIT {limit}"
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
        "count": len(accounts),
        "accounts": accounts,
    }



# ============================================================
# ENTRA TOKEN VALIDATION
# ============================================================

def verify_access_token(token):

    signing_key = (
        entra_jwks_client.get_signing_key_from_jwt(token)
    )

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=API_CLIENT_ID,
        issuer=ENTRA_ISSUER,
    )

    scopes = claims.get("scp", "").split()

    if "access_as_user" not in scopes:
        raise Exception(
            "Required scope access_as_user is missing"
        )

    return claims


def require_auth(route):

    @wraps(route)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get(
            "Authorization",
            ""
        )

        if not auth_header.startswith("Bearer "):

            return jsonify({
                "error": "missing_bearer_token"
            }), 401

        token = auth_header.split(" ", 1)[1]

        try:

            claims = verify_access_token(token)

        except Exception as e:

            return jsonify({
                "error": "invalid_token",
                "details": str(e)
            }), 401

        request.user_claims = claims

        return route(*args, **kwargs)

    return wrapper



# ============================================================
# AI ROUTER
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

    # Required field, but can be null.
    #
    # action == answer:
    #     answer contains the actual response.
    #
    # action == reroute:
    #     answer should be null.
    answer: Optional[str]


ROUTER_INSTRUCTIONS = """
You are the routing and lightweight-answer layer for an
enterprise CRM AI assistant.

You receive ONE user message.

Your job is to do one of two things:

1. ANSWER the request immediately if it is simple and does
   not require private CRM data, current web information,
   tools, workflows, or substantial reasoning.

2. REROUTE the request to the correct model and capability
   level if external data, Salesforce, web search, workflows,
   or more substantial reasoning are required.


============================================================
ROUTES
============================================================

SIMPLE

Use when:
- The request can be answered from general knowledge.
- No Salesforce data is needed.
- No current/live web information is needed.
- No external tools are needed.
- No multi-step workflow is needed.
- No user-specific private information is needed.

For SIMPLE:
action = "answer"
route = "simple"
target_model = "gpt-5.6-luna"
reasoning_effort = "low"
answer = the actual useful answer.


------------------------------------------------------------

CRM_READ

Use when:
- The user wants their Salesforce/CRM information.
- It is primarily retrieval, filtering, lookup, counting,
  or straightforward summarization.
- Little strategic reasoning is required.

Examples:
"How many opportunities do I have?"
"Show my deals above $100k."
"What is the close date of the United Oil opportunity?"

Use:
target_model = "gpt-5.6-luna"
reasoning_effort = "low"
needs_salesforce = true


------------------------------------------------------------

CRM_ANALYSIS

Use when:
- Salesforce data is needed AND the user wants analysis,
  prioritization, comparison, risk assessment,
  recommendations, or strategic interpretation.

Examples:
"Which of my deals are most at risk?"
"Which opportunities should I prioritize this week?"
"Compare my pipeline and tell me where I should focus."

Use:
target_model = "gpt-5.6-terra"
reasoning_effort = "medium" or "high"
needs_salesforce = true


------------------------------------------------------------

WEB_SIMPLE

Use when:
- Current public information is needed.
- The question is relatively straightforward.
- One or a small number of web searches should be enough.

Examples:
"Who is the current CEO of Agilent?"
"Did Thermo Fisher announce anything this week?"

Use:
target_model = "gpt-5.6-terra"
reasoning_effort = "medium"
needs_web = true


------------------------------------------------------------

WEB_RESEARCH

Use when:
- Multiple web searches or sources are likely needed.
- Information must be compared or synthesized.
- CRM information may need to be combined with web data.
- Competitive intelligence or market research is requested.

Examples:
"Research recent United Oil news and tell me how it affects
my opportunities."

"Compare recent Agilent and Waters announcements with my
current pipeline."

Use:
target_model = "gpt-5.6-terra"
reasoning_effort = "high"
needs_web = true

Set needs_salesforce = true when CRM information is also
required.


------------------------------------------------------------

WORKFLOW

Use when:
- The request requires several dependent actions.
- The model must plan and execute multiple tool calls.
- The request includes creating, changing, sending, updating,
  or otherwise modifying state.
- The task combines research, analysis and actions.

Examples:
"Find my best opportunities, research each company and create
follow-up tasks."

"Review all deals closing this month and update the next
steps."

Use:
target_model = "gpt-5.6-terra"
reasoning_effort = "high"

Set needs_write = true if the task changes external data.

Set requires_confirmation = true for consequential writes,
bulk changes, deletions, sending communications, or actions
that cannot easily be undone.


------------------------------------------------------------

DEEP_COMPLEX

Use only when the request involves unusually difficult,
high-value, ambiguous, multi-source strategic reasoning.

Examples:
"Build an executive account strategy across my pipeline,
competitor activity, customer investments and market trends."

"Analyze all available signals and propose a detailed
commercial strategy for the next quarter."

Use:
target_model = "gpt-5.6-sol"
reasoning_effort = "high", "xhigh", or "max"


============================================================
IMPORTANT RULES
============================================================

Never answer a question that depends on Salesforce data
unless you actually have that Salesforce data.

Never pretend you searched the web.

Never invent user-specific CRM information.

If current information is required, route to web access.

If Salesforce information is required, route to Salesforce.

If both are required, mark both needs_web and
needs_salesforce true.

Do not unnecessarily escalate simple requests.

But prefer rerouting over giving an unreliable answer when
external data or stronger reasoning is genuinely required.

routing_note should be a short one-sentence explanation of
why the route was selected. Do not provide hidden reasoning
or a long analysis.

When action is "reroute", answer must be null.

When action is "answer", provide a useful final answer in
answer.
"""

# ============================================================
# CRM AGENT
# ============================================================


CRM_AGENT_INSTRUCTIONS = """
You are an enterprise sales CRM assistant.

The user is authenticated through Microsoft Entra and the
backend has connected to Salesforce using that exact user's
Salesforce permissions.

You have read-only Salesforce tools.

Use the tools whenever the user's question depends on CRM
data.

Never invent CRM values.

Never claim a contact, address, opportunity, account, amount,
date, phone number or email exists unless it was returned by
a tool.

When data is null or missing, say that it is not populated in
Salesforce.

Account billing/shipping addresses represent customer/site
address information.

Contact mailing addresses represent contact-level address
information.

Opportunity contacts are represented using Opportunity
Contact Roles.

For analysis:
- distinguish facts from your interpretation
- use stage, close date, amount, probability, next step and
  other available Salesforce fields
- do not manufacture risk signals that are not present
- explain briefly why you are making a recommendation

You may call multiple tools when necessary.

You currently have NO write tools.
Never claim that you changed Salesforce.
"""


def execute_crm_agent(
    user_message,
    decision,
    sf,
    salesforce_username
):

    # --------------------------------------------------------
    # MODEL FLOOR
    #
    # Router chooses complexity, backend enforces minimum
    # model tier for each route.
    # --------------------------------------------------------

    if decision.route == "crm_read":

        model = "gpt-5.6-luna"


    elif decision.route == "crm_analysis":

        model = "gpt-5.6-terra"


    else:

        raise Exception(
            "Route is not enabled for CRM execution."
        )


    effort = decision.reasoning_effort


    input_items = [

        {
            "role": "developer",

            "content":
                (
                    CRM_AGENT_INSTRUCTIONS
                    + "\n\n"
                    + "Current date: "
                    + date.today().isoformat()
                ),
        },

        {
            "role": "user",
            "content": user_message,
        },
    ]


    tool_trace = []


    # A single user request can have multiple tool rounds.
    # Keep a hard ceiling so a bad agent cannot loop forever.

    for round_number in range(1, 7):


        response = openai_client.responses.create(

            model=model,

            reasoning={
                "effort": effort
            },

            tools=CRM_READ_TOOLS,

            input=input_items,

            store=False,
        )


        # Important for reasoning/tool models:
        # preserve the response items in the next round.

        input_items += response.output


        function_calls = [

            item

            for item in response.output

            if item.type == "function_call"
        ]


        # ----------------------------------------------------
        # NO TOOL CALL = FINAL ANSWER
        # ----------------------------------------------------

        if not function_calls:

            answer = (
                response.output_text
                or ""
            ).strip()


            if not answer:

                answer = (
                    "I couldn't produce a final "
                    "answer from the CRM data."
                )


            return {
                "answer": answer,

                "execution_model": model,

                "reasoning_effort": effort,

                "tool_rounds":
                    round_number - 1,

                "tool_trace":
                    tool_trace,
            }


        # ----------------------------------------------------
        # EXECUTE EVERY TOOL CALL
        # ----------------------------------------------------

        for call in function_calls:


            arguments = json.loads(
                call.arguments
            )


            result = run_crm_tool(

                call.name,

                arguments,

                sf,

                salesforce_username
            )


            tool_trace.append({

                "tool":
                    call.name,

                "arguments":
                    arguments,

                "result_count":
                    result.get("count"),

                "ok":
                    result.get(
                        "ok",
                        False
                    ),
            })


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
        "CRM agent exceeded maximum tool rounds."
    )

def route_or_answer(user_message):

    response = openai_client.responses.parse(
        model="gpt-5.6-luna",

        reasoning={
            "effort": "low"
        },

        store=False,

        input=[
            {
                "role": "developer",
                "content": ROUTER_INSTRUCTIONS,
            },
            {
                "role": "user",
                "content": user_message,
            },
        ],

        text_format=RouteDecision,
    )

    decision = response.output_parsed

    if decision is None:
        raise Exception(
            "OpenAI router returned no parsed decision."
        )

    return decision


# ============================================================
# SALESFORCE JWT AUTHENTICATION
# ============================================================

def get_salesforce_access_token(
    salesforce_username
):

    now = int(time.time())

    payload = {
        "iss": SF_CLIENT_ID,
        "sub": salesforce_username,
        "aud": "https://login.salesforce.com",
        "exp": now + 180,
    }

    assertion = jwt.encode(
        payload,
        get_salesforce_private_key(),
        algorithm="RS256"
    )

    token_url = (
        f"{SF_LOGIN_URL}/services/oauth2/token"
    )

    response = requests.post(
        token_url,
        data={
            "grant_type":
                "urn:ietf:params:oauth:"
                "grant-type:jwt-bearer",

            "assertion": assertion,
        },
        timeout=20,
    )

    if not response.ok:

        # Never log the assertion/private key/access token.
        raise Exception(
            f"Salesforce authentication failed: "
            f"{response.status_code} "
            f"{response.text}"
        )

    token_data = response.json()

    return {
        "access_token":
            token_data["access_token"],

        "instance_url":
            token_data["instance_url"],
    }


# ============================================================
# SALESFORCE QUERY
# ============================================================

def salesforce_query(
    sf_access_token,
    instance_url,
    soql
):

    url = (
        f"{instance_url}"
        f"/services/data/v{SF_API_VERSION}/query"
    )

    response = requests.get(
        url,
        headers={
            "Authorization":
                f"Bearer {sf_access_token}"
        },
        params={
            "q": soql
        },
        timeout=20,
    )

    if not response.ok:

        raise Exception(
            f"Salesforce query failed: "
            f"{response.status_code} "
            f"{response.text}"
        )

    return response.json()


# ============================================================
# BASIC ROUTES
# ============================================================

@app.get("/")
def root():

    return jsonify({
        "service": "CMD AI API",
        "status": "running"
    })


@app.get("/health")
def health():

    return jsonify({
        "ok": True
    })


# ============================================================
# MICROSOFT IDENTITY TEST
# ============================================================

@app.get("/me")
@require_auth
def me():

    claims = request.user_claims

    return jsonify({
        "authenticated": True,

        "name":
            claims.get("name"),

        "username":
            claims.get("preferred_username"),

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
# CHAT - ROUTER TEST VERSION
# ============================================================

# ============================================================
# CHAT
# ============================================================


@app.post("/chat")
@require_auth
def chat():

    body = request.get_json(
        silent=True
    ) or {}


    user_message = (
        body.get("message")
        or ""
    ).strip()


    if not user_message:

        return jsonify({
            "error": "message_required"
        }), 400


    claims = request.user_claims


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
        # 1. LUNA LOW ROUTER
        # ====================================================

        decision = route_or_answer(
            user_message
        )


        route_data = (
            decision.model_dump()
        )


        # ====================================================
        # 2. SIMPLE
        #
        # Router already answered it.
        # ====================================================

        if decision.action == "answer":

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
        # 3. CRM READ / CRM ANALYSIS
        # ====================================================

        if decision.route in {
            "crm_read",
            "crm_analysis"
        }:


            # -----------------------------------------------
            # Get Salesforce token as the authenticated user.
            # -----------------------------------------------

            sf = get_salesforce_access_token(
                salesforce_username
            )


            result = execute_crm_agent(

                user_message,

                decision,

                sf,

                salesforce_username
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
        # 4. ROUTES NOT ENABLED YET
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
# SALESFORCE IDENTITY TEST
# ============================================================

@app.get("/salesforce/me")
@require_auth
def salesforce_me():

    entra_claims = request.user_claims

    entra_username = (
        entra_claims.get("preferred_username")
    )

    if not entra_username:

        return jsonify({
            "error":
                "preferred_username_missing"
        }), 400


    # --------------------------------------------------------
    # CURRENT POC MAPPING
    #
    # Entra preferred_username == Salesforce Username
    #
    # Later this becomes:
    # (tenant_id + oid) -> Salesforce org/user mapping
    # --------------------------------------------------------

    salesforce_username = entra_username


    try:

        sf = get_salesforce_access_token(
            salesforce_username
        )


        # Explicitly restrict this POC query to
        # Opportunities owned by the authenticated user.
        #
        # Username comes from a cryptographically verified
        # Microsoft token, not from client input.

        safe_username = (
            salesforce_username
            .replace("\\", "\\\\")
            .replace("'", "\\'")
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


        opportunity_data = salesforce_query(
            sf["access_token"],
            sf["instance_url"],
            soql
        )


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
                    row.get("StageName"),

                "amount":
                    row.get("Amount"),

                "close_date":
                    row.get("CloseDate"),
            })


        return jsonify({

            "microsoft": {
                "name":
                    entra_claims.get("name"),

                "username":
                    entra_username,

                "oid":
                    entra_claims.get("oid"),

                "tenant_id":
                    entra_claims.get("tid"),
            },

            "salesforce": {
                "connected": True,

                "username":
                    salesforce_username,

                "instance":
                    sf["instance_url"],
            },

            "opportunity_count":
                len(opportunities),

            "opportunities":
                opportunities,
        })


    except Exception as e:

        return jsonify({

            "salesforce_connected": False,

            "microsoft_username":
                entra_username,

            "salesforce_username":
                salesforce_username,

            "error":
                str(e),

        }), 502


# ============================================================
# LOCAL DEV ONLY
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
