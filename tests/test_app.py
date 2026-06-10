"""
PhishGuard – Unit Test Suite
==============================
Run locally :  pytest tests/ -v
Run in CI   :  pytest tests/ -v --cov=App --cov-report=term-missing
"""

import os
import sys
import pytest

# ── Point to project root so App.py is importable ────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("MONGO_URI", "")           # no real DB needed for most tests
os.environ.setdefault("FLASK_DEBUG", "false")
os.environ.setdefault("FIELD_ENCRYPT_KEY",
    "UyBCx0J-2c5DT342T5aSDCPnEpFOiA9A7WKfg0Ujd30=")  # valid Fernet key for tests

import App  # noqa: E402  (must be after env setup)

# ═══════════════════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════════════════
@pytest.fixture
def client():
    App.app.config["TESTING"] = True
    App.app.config["WTF_CSRF_ENABLED"] = False
    with App.app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Client with a valid session token pre-injected."""
    token = App._new_session("testuser")
    yield client, {"X-Auth-Token": token}
    App.sessions.pop(token, None)


# ═══════════════════════════════════════════════════════════════════════════
#  Password hashing
# ═══════════════════════════════════════════════════════════════════════════
class TestPasswordHashing:

    def test_hash_is_bcrypt(self):
        h = App._hash_pw("MyPassword123")
        assert h.startswith("$2b$"), "Hash must be bcrypt"

    def test_hash_is_salted(self):
        h1 = App._hash_pw("SamePassword")
        h2 = App._hash_pw("SamePassword")
        assert h1 != h2, "Each hash must have a unique salt"

    def test_verify_correct_password(self):
        h = App._hash_pw("CorrectHorse99")
        assert App._verify_pw("CorrectHorse99", h) is True

    def test_verify_wrong_password(self):
        h = App._hash_pw("CorrectHorse99")
        assert App._verify_pw("WrongPassword", h) is False

    def test_legacy_sha256_fallback(self):
        import hashlib
        legacy = hashlib.sha256("OldPassword1".encode()).hexdigest()
        assert App._verify_pw("OldPassword1", legacy) is True

    def test_legacy_wrong_password(self):
        import hashlib
        legacy = hashlib.sha256("OldPassword1".encode()).hexdigest()
        assert App._verify_pw("WrongOld", legacy) is False


# ═══════════════════════════════════════════════════════════════════════════
#  Encryption
# ═══════════════════════════════════════════════════════════════════════════
class TestEncryption:

    def test_encrypt_decrypt_roundtrip(self):
        if not App.ENCRYPT_READY:
            pytest.skip("FIELD_ENCRYPT_KEY not set — skipping encryption tests")
        original = "mysecretapppassword"
        encrypted = App._encrypt(original)
        assert encrypted != original
        assert App._decrypt(encrypted) == original

    def test_encrypt_produces_different_ciphertext(self):
        if not App.ENCRYPT_READY:
            pytest.skip("FIELD_ENCRYPT_KEY not set — skipping encryption tests")
        e1 = App._encrypt("samevalue")
        e2 = App._encrypt("samevalue")
        assert e1 != e2

    def test_decrypt_plaintext_fallback(self):
        assert App._decrypt("plaintextvalue") == "plaintextvalue"


# ═══════════════════════════════════════════════════════════════════════════
#  Session management
# ═══════════════════════════════════════════════════════════════════════════
class TestSessions:

    def test_new_session_creates_token(self):
        token = App._new_session("alice")
        assert token in App.sessions
        App.sessions.pop(token, None)

    def test_session_has_expiry(self):
        from datetime import datetime
        token = App._new_session("bob")
        assert "expires_at" in App.sessions[token]
        assert App.sessions[token]["expires_at"] > datetime.utcnow()
        App.sessions.pop(token, None)

    def test_purge_expired_removes_old_tokens(self):
        from datetime import datetime, timedelta
        token = App._new_session("charlie")
        # Force-expire the token
        App.sessions[token]["expires_at"] = datetime.utcnow() - timedelta(seconds=1)
        App._purge_expired()
        assert token not in App.sessions


# ═══════════════════════════════════════════════════════════════════════════
#  Auth middleware
# ═══════════════════════════════════════════════════════════════════════════
class TestAuth:

    def test_no_token_returns_401(self, client):
        r = client.get("/api/history")
        assert r.status_code == 401

    def test_fake_token_returns_401(self, client):
        r = client.get("/api/history",
                       headers={"X-Auth-Token": "a" * 64})
        assert r.status_code == 401

    def test_valid_token_passes(self, auth_client):
        client, headers = auth_client
        r = client.get("/monitor/status", headers=headers)
        assert r.status_code == 200

    def test_expired_token_returns_401(self, client):
        from datetime import datetime, timedelta
        token = App._new_session("expireduser")
        App.sessions[token]["expires_at"] = datetime.utcnow() - timedelta(seconds=1)
        r = client.get("/api/history", headers={"X-Auth-Token": token})
        assert r.status_code == 401
        assert token not in App.sessions


# ═══════════════════════════════════════════════════════════════════════════
#  Security headers
# ═══════════════════════════════════════════════════════════════════════════
class TestSecurityHeaders:

    def test_x_content_type_options(self, auth_client):
        client, headers = auth_client
        r = client.get("/monitor/status", headers=headers)
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, auth_client):
        client, headers = auth_client
        r = client.get("/monitor/status", headers=headers)
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_csp_header_present(self, auth_client):
        client, headers = auth_client
        r = client.get("/monitor/status", headers=headers)
        assert "Content-Security-Policy" in r.headers

    def test_health_requires_auth(self, client):
        r = client.get("/health")
        assert r.status_code == 401

    def test_health_no_mongo_uri_leak(self, auth_client):
        client, headers = auth_client
        r = client.get("/health", headers=headers)
        assert "mongo_uri" not in r.get_data(as_text=True)
        assert "mongodb://" not in r.get_data(as_text=True)


# ═══════════════════════════════════════════════════════════════════════════
#  Analysis engine (rules)
# ═══════════════════════════════════════════════════════════════════════════
class TestAnalysisEngine:

    def test_obvious_phishing_is_high_risk(self):
        result = App.analyze_email(
            sender="security@paypa1.com",
            subject="URGENT: Your account has been suspended",
            body="Click here to verify your account. Update your information now.",
            links="http://paypa1.com/verify\nhttp://bit.ly/abc123",
            headers=""
        )
        assert result["risk"] == "high"
        assert result["risk_score"] >= 65

    def test_clean_email_is_low_risk(self):
        result = App.analyze_email(
            sender="newsletter@github.com",
            subject="Your weekly digest",
            body="Here is your weekly summary of activity on GitHub.",
            links="https://github.com/notifications",
            headers=""
        )
        assert result["risk"] in ("low", "medium")

    def test_ip_address_url_flagged(self):
        result = App.analyze_email(
            sender="test@test.com",
            subject="Hello",
            body="Please visit this link",
            links="http://192.168.1.1/login",
            headers=""
        )
        threats = [t["label"] for t in result["threats"]]
        assert any("IP" in t or "Suspicious" in t for t in threats)

    def test_url_shortener_flagged(self):
        result = App.analyze_email(
            sender="test@test.com",
            subject="Check this out",
            body="Click the link below",
            links="https://bit.ly/abc123",
            headers=""
        )
        link_statuses = [l["status"] for l in result["link_results"]]
        assert "warn" in link_statuses or "danger" in link_statuses

    def test_result_has_required_fields(self):
        result = App.analyze_email("a@b.com", "test", "body", "", "")
        for field in ["risk", "risk_score", "threats", "explanations", "link_results"]:
            assert field in result, f"Missing field: {field}"

    def test_risk_score_in_valid_range(self):
        result = App.analyze_email("a@b.com", "test", "body", "", "")
        assert 0 <= result["risk_score"] <= 100

    def test_spoofed_brand_detected(self):
        result = App.analyze_email(
            sender="support@amaz0n.com",
            subject="Your order",
            body="Hello",
            links="",
            headers=""
        )
        threats = [t["label"] for t in result["threats"]]
        assert any("spoof" in t.lower() or "domain" in t.lower() for t in threats)


# ═══════════════════════════════════════════════════════════════════════════
#  Interview scoring
# ═══════════════════════════════════════════════════════════════════════════
class TestInterviewScoring:

    def test_all_red_flags_raises_score(self):
        answers = {
            "q1": "no",          # unexpected
            "q2": "no",          # unrecognised sender
            "q3": "multiple",    # multiple actions requested
            "q4": "yes",         # urgency/fear
            "q5": "yes",         # part of pattern
        }
        delta, threats, _ = App._interview_score(answers)
        assert delta >= 50, f"Expected high delta, got {delta}"
        assert len(threats) >= 4

    def test_all_safe_answers_zero_delta(self):
        answers = {
            "q1": "yes",
            "q2": "yes",
            "q3": "none",
            "q4": "no",
            "q5": "no",
        }
        delta, threats, _ = App._interview_score(answers)
        assert delta == 0
        assert threats == []

    def test_partial_answers(self):
        answers = {"q1": "no", "q3": "yes_link"}
        delta, _, _ = App._interview_score(answers)
        assert delta > 0


# ═══════════════════════════════════════════════════════════════════════════
#  API endpoints
# ═══════════════════════════════════════════════════════════════════════════
class TestAPIEndpoints:

    def test_analyze_requires_auth(self, client):
        r = client.post("/analyze",
                        json={"sender": "a@b.com", "subject": "test", "body": "hi"},
                        content_type="application/json")
        assert r.status_code == 401

    def test_analyze_empty_body_returns_400(self, auth_client):
        client, headers = auth_client
        r = client.post("/analyze",
                        json={},
                        headers=headers,
                        content_type="application/json")
        assert r.status_code == 400

    def test_analyze_returns_result(self, auth_client):
        client, headers = auth_client
        r = client.post("/analyze",
                        json={"sender": "test@evil.com",
                              "subject": "URGENT verify",
                              "body": "Click here now"},
                        headers=headers,
                        content_type="application/json")
        assert r.status_code == 200
        data = r.get_json()
        assert "risk" in data
        assert "risk_score" in data
        assert "threats" in data

    def test_history_requires_auth(self, client):
        r = client.get("/api/history")
        assert r.status_code == 401

    def test_monitor_status_requires_auth(self, client):
        r = client.get("/monitor/status")
        assert r.status_code == 401

    def test_login_missing_fields_returns_400(self, client):
        r = client.post("/login",
                        json={"username": ""},
                        content_type="application/json")
        assert r.status_code == 400

    def test_login_wrong_credentials_returns_401(self, client):
        r = client.post("/login",
                        json={"username": "ghost_xyz", "password": "wrongpass"},
                        content_type="application/json")
        assert r.status_code == 401