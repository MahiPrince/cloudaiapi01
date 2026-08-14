import os
from functools import wraps

import jwt
from jwt import PyJWKClient
from flask import Flask, jsonify, request


app = Flask(__name__)

TENANT_ID = os.environ["ENTRA_TENANT_ID"]
API_CLIENT_ID = os.environ["ENTRA_API_CLIENT_ID"]

ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

jwks_client = PyJWKClient(JWKS_URL)


def verify_access_token(token):
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=API_CLIENT_ID,
        issuer=ISSUER,
    )

    scopes = claims.get("scp", "").split()

    if "access_as_user" not in scopes:
        raise Exception("Required scope access_as_user is missing")

    return claims


def require_auth(route):
    @wraps(route)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

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


if __name__ == "__main__":
    app.run(debug=True)