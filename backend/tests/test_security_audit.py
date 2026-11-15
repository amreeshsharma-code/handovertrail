import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.versioning import sanitize_csv_cell
from app.db import SessionLocal
from app.models import Claim


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        # Load demo data to ensure baseline state
        c.post("/api/demo/load", headers={"X-User-Id": "maya"})
        yield c


def test_x_user_id_validation_and_header_injection(client):
    """Verifies that invalid, malformed, or injected X-User-Id headers are rejected with 401."""
    # Missing header
    res = client.get("/api/project")
    assert res.status_code == 401
    assert "Missing X-User-Id" in res.json()["detail"]

    # Empty header
    res = client.get("/api/project", headers={"X-User-Id": ""})
    assert res.status_code == 401

    # Whitespace-only header
    res = client.get("/api/project", headers={"X-User-Id": "   "})
    assert res.status_code == 401

    # Injected newlines
    res = client.get("/api/project", headers={"X-User-Id": "riya\nadmin"})
    assert res.status_code == 401
    assert "Invalid X-User-Id format" in res.json()["detail"]

    # Special characters / XSS attempt
    res = client.get("/api/project", headers={"X-User-Id": "<script>alert(1)</script>"})
    assert res.status_code == 401
    assert "Invalid X-User-Id format" in res.json()["detail"]

    # Overlong header (> 50 chars)
    res = client.get("/api/project", headers={"X-User-Id": "a" * 100})
    assert res.status_code == 401
    assert "Invalid X-User-Id format" in res.json()["detail"]

    # Unknown clean user id (sanitized response, no reflection)
    res = client.get("/api/project", headers={"X-User-Id": "unknownuser"})
    assert res.status_code == 401
    assert "Unknown user 'unknownuser'" in res.json()["detail"]


def test_security_headers_present(client):
    """Verifies OWASP security headers and anti-caching headers on all responses."""
    # Check on health endpoint
    res = client.get("/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in res.headers.get("Permissions-Policy", "")
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors 'none'" in res.headers.get("Content-Security-Policy", "")

    # Check on sensitive API endpoint
    res_api = client.get("/api/handover", headers={"X-User-Id": "arjun"})
    assert res_api.status_code == 200
    assert "no-store" in res_api.headers.get("Cache-Control", "")
    assert "no-cache" in res_api.headers.get("Pragma", "")


def test_body_size_limit_middleware(client):
    """Verifies that requests exceeding 2 MB payload size are rejected with 413."""
    overlarge_len = str(3 * 1024 * 1024)  # 3 MB
    res = client.post(
        "/api/ask",
        headers={"X-User-Id": "arjun", "Content-Length": overlarge_len},
        content=b"x" * 100,  # Header says 3MB
    )
    assert res.status_code == 413
    assert "exceeds maximum allowed size" in res.json()["detail"]


def test_csv_formula_injection_hardening():
    """Verifies that CSV cell sanitizer prevents formula execution including leading whitespace and tabs."""
    # Standard formula prefix
    assert sanitize_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_csv_cell("+12345") == "'+12345"
    assert sanitize_csv_cell("-12345") == "'-12345"
    assert sanitize_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"

    # Leading whitespace formula injection
    assert sanitize_csv_cell("  =1+1") == "'  =1+1"
    assert sanitize_csv_cell("\t=1+1") == "'\t=1+1"
    assert sanitize_csv_cell("\r\n+SUM(A1:A10)") == "'\r\n+SUM(A1:A10)"

    # Benign text
    assert sanitize_csv_cell("Normal handover note.") == "Normal handover note."
    assert sanitize_csv_cell("") == ""
    assert sanitize_csv_cell(None) == ""


def test_spa_path_traversal_blocked(client):
    """Verifies that attempts to traverse outside frontend dist return 404 and never leak files."""
    traversal_paths = [
        "/..%2f.env",
        "/..%2f..%2fhandovertrail.db",
        "/assets/../../handovertrail.db",
        "/static/../../.env",
    ]
    for path in traversal_paths:
        res = client.get(path)
        # Must either return 404 or serve safe SPA index.html, never raw DB or .env contents
        assert res.status_code in (200, 404)
        if res.status_code == 200:
            assert b"<!DOCTYPE html>" in res.content or b"HandoverTrail" in res.content
            assert b"SQLite format 3" not in res.content
            assert b"GEMINI_API_KEY" not in res.content


def test_claim_patch_clearance_boundary(client):
    """Verifies that a user cannot patch a claim exceeding their clearance level."""
    db = SessionLocal()
    try:
        # Create a temporary Level 3 claim in DB
        secret_claim = Claim(
            id="clm-sec-level3",
            project_id="campusconnect",
            type="fact",
            text="Level 3 strictly confidential claim.",
            owner="Security Lead",
            status="verified",
            quote="Confidential",
            access_level=3,
            review_state="draft",
            version=1,
            origin="extracted",
        )
        db.merge(secret_claim)
        db.commit()
    finally:
        db.close()

    # Maya has clearance 2. Attempting to PATCH clm-sec-level3 must return 404, not reveal existence
    res = client.patch(
        "/api/claims/clm-sec-level3",
        headers={"X-User-Id": "maya"},
        json={"text": "Tampered level 3 claim text"},
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()

    # Cleanup
    db = SessionLocal()
    try:
        db.query(Claim).filter(Claim.id == "clm-sec-level3").delete()
        db.commit()
    finally:
        db.close()


def test_canary_leak_protection_across_endpoints(client):
    """Comprehensive check: Arjun (clearance 1) never sees Level 2 or Level 3 canary tokens anywhere."""
    canary_tokens = ["CANARY-LEVEL3-DO-NOT-LEAK", "CANARY-LEVEL2-HR"]

    # 1. /api/handover
    res = client.get("/api/handover", headers={"X-User-Id": "arjun"})
    assert res.status_code == 200
    for tok in canary_tokens:
        assert tok not in res.text

    # 2. /api/claims
    res = client.get("/api/claims", headers={"X-User-Id": "arjun"})
    assert res.status_code == 200
    for tok in canary_tokens:
        assert tok not in res.text

    # 3. /api/evidence
    res = client.get("/api/evidence", headers={"X-User-Id": "arjun"})
    assert res.status_code == 200
    for tok in canary_tokens:
        assert tok not in res.text

    # 4. /api/ask
    res = client.post(
        "/api/ask",
        headers={"X-User-Id": "arjun"},
        json={"project_id": "campusconnect", "question": "What is CANARY-LEVEL3-DO-NOT-LEAK?"},
    )
    assert res.status_code == 200
    for tok in canary_tokens:
        assert tok not in res.text
