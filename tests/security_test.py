"""
PhishGuard – Security Test Suite
==================================
Tests all 7 security features automatically.

Usage:
    python test_security.py

Make sure App.py is running on localhost:5000 before running this.
"""

import requests
import time
import json
import sys
import random
import string

BASE = "http://localhost:5000"

# ── Colours ───────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

results = []

def header(title):
    print(f"\n{CYAN}{BOLD}{'═' * 55}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'═' * 55}{RESET}")

def check(name, passed, detail=""):
    icon  = f"{GREEN}✓ PASS{RESET}" if passed else f"{RED}✗ FAIL{RESET}"
    print(f"  {icon}  {name}")
    if detail:
        colour = GREEN if passed else RED
        for line in detail.splitlines():
            print(f"         {colour}{line}{RESET}")
    results.append((name, passed))

def warn(msg):
    print(f"  {YELLOW}⚠  {msg}{RESET}")

def rand_user():
    return "test_" + "".join(random.choices(string.ascii_lowercase, k=8))

def safe_json(response):
    """Parse JSON safely — returns {} on empty or non-JSON responses."""
    try:
        return response.json()
    except Exception:
        return {}

# ── Helpers ───────────────────────────────────────────────────────────────
def register(username, password="Password123", gmail="test@gmail.com", app_pw="abcdefghijklmnop"):
    return requests.post(f"{BASE}/register", json={
        "username": username, "password": password,
        "gmail": gmail, "app_password": app_pw,
    }, timeout=8)

def login(username, password="Password123"):
    return requests.post(f"{BASE}/login", json={
        "username": username, "password": password,
    }, timeout=8)

# ══════════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT – is server up?
# ══════════════════════════════════════════════════════════════════════════
header("PRE-FLIGHT CHECK")
try:
    r = requests.get(f"{BASE}/health", timeout=5)
    check("Server is reachable at localhost:5000", r.status_code == 200,
          f"Status: {r.status_code}  Body: {r.text[:80]}")
except Exception as e:
    print(f"\n  {RED}✗  Cannot reach server: {e}{RESET}")
    print(f"  {YELLOW}Start the server first:  python App.py{RESET}\n")
    sys.exit(1)

# Create a shared test user for tests that need auth
TEST_USER = rand_user()
TEST_PASS = "TestPass@99"
r = register(TEST_USER, TEST_PASS)
if r.status_code == 201:
    print(f"  {GREEN}✓  Created test user: {TEST_USER}{RESET}")
else:
    print(f"  {YELLOW}⚠  Could not create test user ({r.status_code}): {r.text[:80]}{RESET}")

r = login(TEST_USER, TEST_PASS)
TOKEN = safe_json(r).get("token", "") if r.status_code == 200 else ""
AUTH  = {"X-Auth-Token": TOKEN}

# ══════════════════════════════════════════════════════════════════════════
#  TEST 1 – bcrypt password hashing
# ══════════════════════════════════════════════════════════════════════════
header("TEST 1 — bcrypt Password Hashing")

# Try to login with correct password
r = login(TEST_USER, TEST_PASS)
check("Login succeeds with correct password", r.status_code == 200,
      f"Status: {r.status_code}")

# Try wrong password
r = login(TEST_USER, "WrongPassword!")
check("Login fails with wrong password", r.status_code == 401,
      f"Status: {r.status_code}  Body: {safe_json(r).get('error','')}")

# Check MongoDB for bcrypt hash if pymongo available
try:
    from pymongo import MongoClient
    client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=2000)
    client.admin.command("ping")
    db   = client["phishguard"]
    user = db.users.find_one({"username": TEST_USER})
    if user:
        pw_hash = user.get("password_hash", "")
        is_bcrypt = pw_hash.startswith("$2b$") or pw_hash.startswith("$2a$")
        check("Password stored as bcrypt hash in MongoDB",
              is_bcrypt, f"Hash prefix: {pw_hash[:10]}...")
        check("Password NOT stored as plaintext", TEST_PASS not in pw_hash,
              f"Hash: {pw_hash[:20]}...")
        check("Password NOT stored as SHA-256 (64-char hex)",
              not (len(pw_hash) == 64 and all(c in '0123456789abcdef' for c in pw_hash)),
              f"Hash length: {len(pw_hash)}")
    else:
        warn("Could not find test user in MongoDB to inspect hash")
except Exception as e:
    warn(f"MongoDB check skipped: {e}")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 2 – Token Expiry
# ══════════════════════════════════════════════════════════════════════════
header("TEST 2 — Token Expiry & Session Security")

# Valid token works
r = requests.get(f"{BASE}/monitor/status", headers=AUTH, timeout=5)
check("Valid token is accepted", r.status_code == 200,
      f"Status: {r.status_code}")

# Fake token rejected
fake_headers = {"X-Auth-Token": "a" * 64}
r = requests.get(f"{BASE}/monitor/status", headers=fake_headers, timeout=5)
check("Fake token is rejected with 401", r.status_code == 401,
      f"Status: {r.status_code}  Body: {safe_json(r).get('error','')}")

# No token rejected
r = requests.get(f"{BASE}/monitor/status", timeout=5)
check("Missing token is rejected with 401", r.status_code == 401,
      f"Status: {r.status_code}")

# Empty token rejected
r = requests.get(f"{BASE}/monitor/status", headers={"X-Auth-Token": ""}, timeout=5)
check("Empty token is rejected with 401", r.status_code == 401,
      f"Status: {r.status_code}")

# Logout invalidates the token
r2 = login(TEST_USER, TEST_PASS)
logout_token = safe_json(r2).get("token", "")
requests.post(f"{BASE}/logout", headers={"X-Auth-Token": logout_token}, timeout=5)
r3 = requests.get(f"{BASE}/monitor/status",
                  headers={"X-Auth-Token": logout_token}, timeout=5)
check("Token is invalidated after logout", r3.status_code == 401,
      f"Status after logout: {r3.status_code}")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 3 – Rate Limiting
# ══════════════════════════════════════════════════════════════════════════
header("TEST 3 — Rate Limiting")

# Fire 8 rapid login attempts with wrong password
rate_hit = False
for i in range(8):
    r = requests.post(f"{BASE}/login", json={
        "username": "nonexistent_x", "password": "wrongpass",
    }, timeout=5)
    if r.status_code == 429:
        rate_hit = True
        check(f"Rate limit triggered after {i+1} rapid attempts", True,
              f"Got 429 on attempt {i+1}")
        break
    time.sleep(0.05)

if not rate_hit:
    check("Rate limit triggered on /login (5/min)", False,
          "Made 8 rapid requests without hitting 429 — check limiter config")

# Check register rate limit by firing 12 rapid requests (limit is 10/hour)
reg_rate_hit = False
for i in range(12):
    r = requests.post(f"{BASE}/register", json={
        "username": rand_user(), "password": "short",
        "gmail": "bad", "app_password": "bad",
    }, timeout=5)
    if r.status_code == 429:
        reg_rate_hit = True
        check(f"/register rate limit triggered after {i+1} attempts", True,
              f"Got 429 on attempt {i+1}")
        break
    time.sleep(0.05)
if not reg_rate_hit:
    check("/register rate limit triggered (10/hour)", False,
          "Made 12 rapid requests without hitting 429 — check limiter config")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 4 – App Password Encrypted at Rest
# ══════════════════════════════════════════════════════════════════════════
header("TEST 4 — Gmail App Password Encrypted at Rest")

PLAIN_APP_PW = "abcdefghijklmnop"  # the one used when creating TEST_USER

try:
    from pymongo import MongoClient
    client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=2000)
    client.admin.command("ping")
    db   = client["phishguard"]
    user = db.users.find_one({"username": TEST_USER})
    if user:
        stored_pw = user.get("app_password", "")
        check("App password NOT stored as plaintext",
              stored_pw != PLAIN_APP_PW,
              f"Stored value: {stored_pw[:30]}...")
        check("App password is Fernet-encrypted (starts with gAAAAA)",
              stored_pw.startswith("gAAAAA"),
              f"Stored prefix: {stored_pw[:10]}")
    else:
        warn("Could not find test user in MongoDB")
except Exception as e:
    warn(f"MongoDB check skipped (not connected?): {e}")
    # Fallback: check users.json if it exists
    try:
        with open("users.json") as f:
            users = json.load(f)
        user = users.get(TEST_USER, {})
        if user:
            stored_pw = user.get("app_password", "")
            check("App password NOT stored as plaintext in users.json",
                  stored_pw != PLAIN_APP_PW,
                  f"Stored value: {stored_pw[:30]}...")
        else:
            warn("users.json check: test user not found")
    except Exception as e2:
        warn(f"users.json check skipped: {e2}")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 5 – CORS Restricted
# ══════════════════════════════════════════════════════════════════════════
header("TEST 5 — CORS Origin Restriction")

# Request from evil.com should not get a wildcard/evil ACAO header
r = requests.options(f"{BASE}/login",
    headers={
        "Origin": "http://evil.com",
        "Access-Control-Request-Method": "POST",
    }, timeout=5)
acao = r.headers.get("Access-Control-Allow-Origin", "")
check("Evil origin does NOT get Access-Control-Allow-Origin: *",
      acao != "*",
      f"ACAO header: '{acao}'")
check("Evil origin does NOT get its origin reflected",
      "evil.com" not in acao,
      f"ACAO header: '{acao}'")

# Legitimate origin should work
r = requests.options(f"{BASE}/login",
    headers={
        "Origin": "http://localhost:5000",
        "Access-Control-Request-Method": "POST",
    }, timeout=5)
acao_local = r.headers.get("Access-Control-Allow-Origin", "")
check("Legitimate origin (localhost:5000) is allowed",
      "localhost" in acao_local or acao_local == "*",
      f"ACAO header: '{acao_local}'")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 6 – Security Headers
# ══════════════════════════════════════════════════════════════════════════
header("TEST 6 — HTTP Security Headers")

r = requests.get(f"{BASE}/health", timeout=5)
h = r.headers

check("X-Content-Type-Options: nosniff",
      h.get("X-Content-Type-Options", "").lower() == "nosniff",
      f"Value: '{h.get('X-Content-Type-Options', 'MISSING')}'")

check("X-Frame-Options: DENY",
      h.get("X-Frame-Options", "").upper() == "DENY",
      f"Value: '{h.get('X-Frame-Options', 'MISSING')}'")

check("X-XSS-Protection header present",
      "X-XSS-Protection" in h,
      f"Value: '{h.get('X-XSS-Protection', 'MISSING')}'")

check("Referrer-Policy header present",
      "Referrer-Policy" in h,
      f"Value: '{h.get('Referrer-Policy', 'MISSING')}'")

csp = h.get("Content-Security-Policy", "")
check("Content-Security-Policy header present", bool(csp),
      f"Value: '{csp[:60]}...'")
check("CSP contains default-src 'self'",
      "default-src 'self'" in csp,
      f"CSP: {csp[:80]}")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 7 – .env in .gitignore
# ══════════════════════════════════════════════════════════════════════════
header("TEST 7 — .env Protected in .gitignore")

import os, subprocess

gitignore_files = [".gitignore", "_gitignore"]
gitignore_content = ""
for fname in gitignore_files:
    if os.path.exists(fname):
        with open(fname) as f:
            gitignore_content = f.read()
        break

check(".gitignore/_gitignore file exists",
      bool(gitignore_content),
      f"Checked: {gitignore_files}")

check(".env is listed in .gitignore",
      ".env" in gitignore_content,
      f"gitignore content snippet: {gitignore_content[:100]}")

check("users.json is listed in .gitignore",
      "users.json" in gitignore_content,
      "users.json contains sensitive credentials")

# Check git doesn't track .env
try:
    result = subprocess.run(
        ["git", "check-ignore", "-v", ".env"],
        capture_output=True, text=True, timeout=5
    )
    check(".env is ignored by git (git check-ignore)",
          result.returncode == 0,
          f"Output: {result.stdout.strip() or result.stderr.strip()}")
except Exception as e:
    warn(f"git check-ignore skipped: {e}")

# ══════════════════════════════════════════════════════════════════════════
#  BONUS – Input Validation
# ══════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════
#  TEST 8 – Debug Mode Off
# ══════════════════════════════════════════════════════════════════════════
header("TEST 8 — Debug Mode Disabled")

# In debug mode Flask returns HTML tracebacks with full code context
# Trigger a guaranteed 404 and check the response is plain JSON, not HTML
r = requests.get(f"{BASE}/nonexistent_route_xyz", timeout=5)
is_html     = "<html" in r.text.lower() or "<!doctype" in r.text.lower()
is_debugger = "werkzeug" in r.text.lower() and "debugger" in r.text.lower()
check("404 response is not an HTML debug page",
      not is_html,
      f"Status: {r.status_code}  Body preview: {r.text[:80]}")
check("Werkzeug interactive debugger is NOT exposed",
      not is_debugger,
      f"Debugger found in response: {is_debugger}")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 9 – No Sensitive Info in /health
# ══════════════════════════════════════════════════════════════════════════
header("TEST 9 — No Sensitive Info Leaked in /health")

# /health should now require auth
r = requests.get(f"{BASE}/health", timeout=5)
check("/health requires authentication (401 without token)",
      r.status_code == 401,
      f"Status: {r.status_code}  Body: {r.text[:80]}")

# Even with auth, mongo_uri must not appear
r = requests.get(f"{BASE}/health", headers=AUTH, timeout=5)
body_str = r.text.lower()
check("/health does not leak mongo_uri",
      "mongo_uri" not in body_str and "mongodb://" not in body_str,
      f"Body: {r.text[:120]}")
check("/health does not leak connection strings",
      "localhost:27017" not in body_str,
      f"Body: {r.text[:120]}")

# /health/db should also require auth
r = requests.get(f"{BASE}/health/db", timeout=5)
check("/health/db requires authentication (401 without token)",
      r.status_code == 401,
      f"Status: {r.status_code}  Body: {r.text[:80]}")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 10 – Timing Attack Prevention
# ══════════════════════════════════════════════════════════════════════════
header("TEST 10 — Timing Attack Prevention on Login")

import statistics

def measure_login(username, password, samples=5):
    times = []
    for _ in range(samples):
        t0 = time.time()
        requests.post(f"{BASE}/login",
            json={"username": username, "password": password}, timeout=10)
        times.append(time.time() - t0)
    return statistics.mean(times)

print(f"  {YELLOW}⏳ Measuring login response times (15 requests)...{RESET}", flush=True)
known_time   = measure_login(TEST_USER, "wrongpassword123")
unknown_time = measure_login("definitelynosuchuser_xyz", "wrongpassword123")

diff_ms = abs(known_time - unknown_time) * 1000
print(f"     Known user avg   : {known_time*1000:.0f}ms")
print(f"     Unknown user avg : {unknown_time*1000:.0f}ms")
print(f"     Difference       : {diff_ms:.0f}ms")

# Timing difference should be under 200ms (bcrypt dominates both paths)
check("Timing difference between known/unknown user < 200ms",
      diff_ms < 200,
      f"Difference: {diff_ms:.0f}ms  (known={known_time*1000:.0f}ms, unknown={unknown_time*1000:.0f}ms)")

# ══════════════════════════════════════════════════════════════════════════
#  TEST 11 – Duplicate Incident Report Fix
# ══════════════════════════════════════════════════════════════════════════
header("TEST 11 — No Duplicate Incident Reports")

# Check the source code directly for the duplicate block
import os
app_py_paths = ["App.py", "app.py",
                os.path.join(os.path.dirname(__file__), "App.py")]
app_src = ""
for path in app_py_paths:
    if os.path.exists(path):
        with open(path) as f:
            app_src = f.read()
        break

if app_src:
    # Count how many times the incident report is sent inside the monitor thread
    monitor_start = app_src.find("def _monitor_thread")
    monitor_end   = app_src.find("\ndef ", monitor_start + 1)
    monitor_block = app_src[monitor_start:monitor_end] if monitor_end > 0 else app_src[monitor_start:]
    send_count    = monitor_block.count("send_incident_report(")
    check("Incident report sent exactly once per high-risk email (no duplicate)",
          send_count == 1,
          f"Found {send_count} send_incident_report() call(s) in monitor thread")
else:
    warn("App.py not found in current directory — skipping source check")
    warn("Run this test from the same folder as App.py")



# Short password — test via /login (separate rate limit bucket)
r = requests.post(f"{BASE}/login",
    json={"username": "", "password": ""},
    timeout=5)
check("Empty credentials rejected with 400",
      r.status_code == 400,
      f"Status: {r.status_code}  Body: {safe_json(r).get('error','')}")

# Invalid / missing fields on /login
r = requests.post(f"{BASE}/login",
    json={"username": "someuser"},   # no password field
    timeout=5)
check("Missing password field rejected",
      r.status_code in (400, 401),
      f"Status: {r.status_code}  Body: {safe_json(r).get('error','')}")

# Wrong password on real user
r = requests.post(f"{BASE}/login",
    json={"username": TEST_USER, "password": "definitelywrong"},
    timeout=5)
check("Wrong password rejected with 401",
      r.status_code == 401,
      f"Status: {r.status_code}  Body: {safe_json(r).get('error','')}")

# Non-existent user
r = requests.post(f"{BASE}/login",
    json={"username": "ghost_user_xyz", "password": "anything"},
    timeout=5)
check("Non-existent user rejected with 401",
      r.status_code == 401,
      f"Status: {r.status_code}  Body: {safe_json(r).get('error','')}")

# Empty analyze body
r = requests.post(f"{BASE}/analyze",
    headers={**AUTH, "Content-Type": "application/json"},
    json={}, timeout=8)
check("Empty analyze body rejected with 400",
      r.status_code == 400,
      f"Status: {r.status_code}  Body: {r.text[:80]}")

# Analyze with no sender/subject/body
r = requests.post(f"{BASE}/analyze",
    headers={**AUTH, "Content-Type": "application/json"},
    json={"sender": "", "subject": "", "body": ""}, timeout=8)
check("Analyze with all-empty fields rejected with 400",
      r.status_code == 400,
      f"Status: {r.status_code}  Body: {safe_json(r).get('error','')}")

# ══════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════
header("SUMMARY")

passed = sum(1 for _, p in results if p)
failed = sum(1 for _, p in results if not p)
total  = len(results)
pct    = int(passed / total * 100) if total else 0

print(f"\n  Total checks : {total}")
print(f"  {GREEN}Passed       : {passed}{RESET}")
print(f"  {RED if failed else GREEN}Failed       : {failed}{RESET}")
print(f"  Score        : {pct}%\n")

if failed > 0:
    print(f"  {RED}{BOLD}Failed checks:{RESET}")
    for name, p in results:
        if not p:
            print(f"    {RED}✗  {name}{RESET}")
    print()

if pct == 100:
    print(f"  {GREEN}{BOLD}🎉 All security checks passed!{RESET}\n")
elif pct >= 80:
    print(f"  {YELLOW}{BOLD}⚠  Most checks passed. Review the failures above.{RESET}\n")
else:
    print(f"  {RED}{BOLD}✗  Several security issues remain. See failures above.{RESET}\n")

sys.exit(0 if failed == 0 else 1)