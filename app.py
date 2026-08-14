import os
import time
from functools import wraps

import jwt
import requests
from jwt import PyJWKClient
from flask import Flask, jsonify, request
from typing import Literal, Optional

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

@app.post("/chat")
@require_auth
def chat():

    data = request.get_json(
        silent=True
    ) or {}

    message = (
        data.get("message")
        or ""
    ).strip()

    if not message:

        return jsonify({
            "error": "message_required"
        }), 400


    claims = request.user_claims

    try:

        decision = route_or_answer(
            message
        )

        result = decision.model_dump()


        # --------------------------------------------
        # SIMPLE
        #
        # Luna already answered it.
        # No second model call required.
        # --------------------------------------------

        if decision.action == "answer":

            return jsonify({

                "status":
                    "answered",

                "router_model":
                    "gpt-5.6-luna",

                "user":
                    claims.get(
                        "preferred_username"
                    ),

                "route":
                    result,

                "answer":
                    decision.answer,
            })


        # --------------------------------------------
        # REROUTED
        #
        # In THIS TEST VERSION we deliberately
        # stop here.
        #
        # Next build will actually execute this.
        # --------------------------------------------

        return jsonify({

            "status":
                "routed",

            "router_model":
                "gpt-5.6-luna",

            "user":
                claims.get(
                    "preferred_username"
                ),

            "route":
                result,

            "message":
                (
                    "Routing successful. "
                    "Execution is not enabled yet."
                ),
        })


    except Exception as e:

        return jsonify({

            "error":
                "router_failed",

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
