import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_tmp = tempfile.TemporaryDirectory()
os.environ.setdefault("ENTRA_TENANT_ID", "00000000-0000-0000-0000-000000000001")
os.environ.setdefault("ENTRA_API_CLIENT_ID", "00000000-0000-0000-0000-000000000002")
os.environ.setdefault("SF_CLIENT_ID", "dummy-client")
os.environ.setdefault("SF_LOGIN_URL", "https://login.salesforce.com")
os.environ.setdefault("SF_JWT_PRIVATE_KEY", "dummy-private-key")
os.environ.setdefault("OPENAI_API_KEY", "sk-test-not-real")
os.environ.setdefault("APP_SIGNING_SECRET", "test-signing-secret-012345678901234567890123456789")
os.environ["SESSION_STORAGE_ROOT"] = _tmp.name
os.environ["MEYORA_FIELD_ADAPTER_TOKEN"] = "test-adapter-token"
os.environ["MEYORA_PRINCIPALS_JSON"] = json.dumps([
    {
        "principal_id": "alice-sales",
        "display_name": "Alice Rep",
        "role": "Account Manager",
        "domain": "sales",
        "match": {
            "oid": "alice-oid",
            "username": "alice@example.test",
        },
    },
    {
        "principal_id": "maya-field",
        "display_name": "Maya Iyer",
        "role": "Senior Field Service Engineer",
        "domain": "field_service",
        "match": {
            "oid": "maya-oid",
            "username": "maya@example.test",
        },
    },
])

import app as backend


def _insert(session_id, oid, upn):
    claims = {"oid": oid, "preferred_username": upn}
    principal = backend.session_principal_from_claims(claims)
    audio_dir = Path(_tmp.name) / "test-audio" / session_id
    audio_dir.mkdir(parents=True, exist_ok=True)
    audio = audio_dir / "original.m4a"
    audio.write_bytes(b"test-audio-placeholder")
    backend.insert_or_replace_uploaded_session(
        session_id,
        claims,
        upn,
        {
            "title": "Processing session",
            "source": "iphone",
            "started_at": "2026-09-21T09:00:00+05:30",
            "ended_at": "2026-09-21T09:15:00+05:30",
            "duration_ms": 900000,
        },
        audio,
        audio.stat().st_size,
        None,
        None,
        principal=principal,
    )
    return principal


def main():
    maya = _insert("sess_maya_test_01", "maya-oid", "maya@example.test")
    alice = _insert("sess_alice_test_01", "alice-oid", "alice@example.test")

    assert maya["domain"] == "field_service"
    assert alice["domain"] == "sales"

    maya_row = backend.owner_session_row("sess_maya_test_01", "maya-oid")
    alice_row = backend.owner_session_row("sess_alice_test_01", "alice-oid")
    assert maya_row["domain"] == "field_service"
    assert maya_row["principal_id"] == "maya-field"
    assert alice_row["domain"] == "sales"
    assert alice_row["principal_id"] == "alice-sales"

    maya_public = backend.session_row_to_dict(maya_row, include_summary=False)
    alice_public = backend.session_row_to_dict(alice_row, include_summary=False)
    assert maya_public["domain"] == "field_service"
    assert alice_public["domain"] == "sales"

    # Simulate a pre-V4.6 Maya row and verify API serialization infers the correct domain.
    with backend.session_db() as conn:
        conn.execute(
            "UPDATE sessions SET domain=NULL, principal_id=NULL WHERE session_id=?",
            ("sess_maya_test_01",),
        )
        conn.commit()
    legacy_row = backend.owner_session_row("sess_maya_test_01", "maya-oid")
    inferred = backend.session_row_to_dict(legacy_row, include_summary=False)
    assert inferred["domain"] == "field_service"
    assert inferred["principal_id"] == "maya-field"

    print(json.dumps({
        "ok": True,
        "maya_domain": maya_public["domain"],
        "alice_domain": alice_public["domain"],
        "legacy_inference": inferred["domain"],
    }))


if __name__ == "__main__":
    main()
