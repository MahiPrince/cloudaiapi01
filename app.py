import os
import time
from functools import wraps

import jwt
import requests
from jwt import PyJWKClient
from flask import Flask, jsonify, request


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

SF_CONSUMER_KEY = os.environ["SF_CONSUMER_KEY"]

SF_MY_DOMAIN_URL = (
    os.environ["SF_MY_DOMAIN_URL"].rstrip("/")
)

SF_JWT_AUDIENCE = os.environ.get(
    "SF_JWT_AUDIENCE",
    "https://login.salesforce.com"
)

SF_API_VERSION = "67.0"


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