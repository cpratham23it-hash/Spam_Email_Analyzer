"""
PhishGuard – Flask API  (v4 – MongoDB integration)
====================================================
Changes from v3:
  • MongoDB replaces users.json  → users stored in db.users collection
  • MongoDB replaces in-memory deque/stats → scans stored in db.scans
  • Stats are computed live via MongoDB aggregation (persist across restarts)
  • /api/dashboard now reads from MongoDB (last 200 scans, live stats)
  • /api/scans/<id>  – fetch a single scan document by Mongo _id
  • All auth, monitor, analyze routes unchanged in behaviour
  • Graceful fallback: if MongoDB is unreachable the app still starts
    (ML + rules analysis works; dashboard shows empty state)

MongoDB URI: set env var  MONGO_URI  or defaults to localhost:27017
Database   : phishguard
Collections: users, scans
"""

from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
import re, os, json, logging, hashlib, secrets, threading
from datetime import datetime
from functools import wraps

# ── MongoDB setup ───────────────────────────────────────────────────────
try:
    from pymongo import MongoClient, DESCENDING
    from pymongo.errors import ConnectionFailure, OperationFailure
    from bson import ObjectId
    from bson.errors import InvalidId

    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    _mongo_client.admin.command("ping")          # test connection
    _db        = _mongo_client["phishguard"]
    _users_col = _db["users"]
    _scans_col = _db["scans"]

    # Indexes for fast lookups
    _users_col.create_index("username", unique=True)
    _scans_col.create_index([("created_at", DESCENDING)])
    _scans_col.create_index("user")
    _scans_col.create_index("risk")

    MONGO_READY = True
    print("  [MongoDB] Connected → phishguard database")

except Exception as _me:
    MONGO_READY = False
    _db = _users_col = _scans_col = None
    print(f"  [MongoDB] Unavailable ({_me}) – falling back to users.json / in-memory")

# ── ML (optional) ──────────────────────────────────────────────────────
try:
    import joblib, numpy as np
    _MODEL_PATH = os.path.join("model", "model.pkl")
    _VEC_PATH   = os.path.join("model", "vectorizer.pkl")
    if os.path.exists(_MODEL_PATH) and os.path.exists(_VEC_PATH):
        _clf = joblib.load(_MODEL_PATH)
        _vec = joblib.load(_VEC_PATH)
        ML_READY = True
        print("  [ML] Model loaded → ML + rules mode")
    else:
        ML_READY = False
        print("  [ML] model.pkl not found → rules-only mode")
except ImportError:
    ML_READY = False

import re as _re
import nltk
nltk.download("stopwords", quiet=True)
from nltk.corpus import stopwords as _sw
_STOP    = set(_sw.words("english"))
_URL_RE  = _re.compile(r"http\S+|www\S+")
_MAIL_RE = _re.compile(r"\S+@\S+")
_NALPHA  = _re.compile(r"[^a-z\s]")
_SPC     = _re.compile(r"\s+")

def _clean(text):
    if not isinstance(text, str): return ""
    t = text.lower()
    t = _URL_RE.sub(" urltoken ", t)
    t = _MAIL_RE.sub(" emailtoken ", t)
    t = _NALPHA.sub(" ", t)
    tokens = [w for w in _SPC.sub(" ", t).split() if w not in _STOP and len(w) > 2]
    return " ".join(tokens)

# ── App setup ───────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=".")
CORS(app, supports_credentials=True)
logging.basicConfig(level=logging.INFO)

# In-memory fallback (used only when MongoDB is down)
from collections import deque
_fallback_scan_log = deque(maxlen=200)
_fallback_stats    = {"total": 0, "high": 0, "medium": 0, "low": 0}

# ── User store helpers (Mongo-first, JSON fallback) ─────────────────────
USERS_FILE = "users.json"

def _load_users():
    """Return dict keyed by username."""
    if MONGO_READY:
        try:
            docs = list(_users_col.find({}, {"_id": 0}))
            return {d["username"]: d for d in docs}
        except Exception:
            pass
    # JSON fallback
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _get_user(username: str):
    """Fetch a single user doc."""
    if MONGO_READY:
        try:
            return _users_col.find_one({"username": username}, {"_id": 0})
        except Exception:
            pass
    return _load_users().get(username)

def _save_user(username: str, doc: dict):
    """Upsert a user document."""
    if MONGO_READY:
        try:
            doc["username"] = username
            _users_col.update_one(
                {"username": username},
                {"$set": doc},
                upsert=True,
            )
            return
        except Exception as e:
            print(f"  [MongoDB] _save_user error: {e}")
    # JSON fallback
    users = _load_users()
    users[username] = doc
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def _user_exists(username: str) -> bool:
    if MONGO_READY:
        try:
            return _users_col.count_documents({"username": username}) > 0
        except Exception:
            pass
    return username in _load_users()

def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ── Scan store helpers (Mongo-first, deque fallback) ────────────────────

def _save_scan(entry: dict):
    """Persist a scan entry to MongoDB (or fallback deque)."""
    if MONGO_READY:
        try:
            doc = dict(entry)
            doc["created_at"] = datetime.utcnow()
            result = _scans_col.insert_one(doc)
            entry["_id"] = str(result.inserted_id)
            return
        except Exception as e:
            print(f"  [MongoDB] _save_scan error: {e}")
    _fallback_scan_log.appendleft(entry)

def _get_scans(limit: int = 200):
    """Return the most recent scans as plain dicts."""
    if MONGO_READY:
        try:
            cursor = _scans_col.find(
                {}, {"_id": 1, "id": 1, "time": 1, "date": 1,
                     "sender": 1, "subject": 1, "risk": 1,
                     "risk_score": 1, "threats": 1, "source": 1,
                     "mode": 1, "user": 1}
            ).sort("created_at", DESCENDING).limit(limit)
            docs = []
            for d in cursor:
                d["_id"] = str(d["_id"])
                docs.append(d)
            return docs
        except Exception as e:
            print(f"  [MongoDB] _get_scans error: {e}")
    return list(_fallback_scan_log)

def _get_stats():
    """Compute live stats from MongoDB aggregation, or return in-memory fallback."""
    if MONGO_READY:
        try:
            pipeline = [
                {"$group": {
                    "_id": "$risk",
                    "count": {"$sum": 1}
                }}
            ]
            agg = {doc["_id"]: doc["count"] for doc in _scans_col.aggregate(pipeline)}
            total = sum(agg.values())
            return {
                "total":  total,
                "high":   agg.get("high",   0),
                "medium": agg.get("medium", 0),
                "low":    agg.get("low",    0),
            }
        except Exception as e:
            print(f"  [MongoDB] _get_stats error: {e}")
    return dict(_fallback_stats)

def _increment_fallback_stats(risk: str):
    """Only used in fallback (no-Mongo) mode."""
    _fallback_stats["total"] += 1
    _fallback_stats[risk]    += 1

# ── In-memory session store  {token: username} ─────────────────────────
sessions = {}

# ── Auth decorator ──────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Auth-Token") or request.args.get("token")
        if not token or token not in sessions:
            return jsonify({"error": "Unauthorized"}), 401
        g.username = sessions[token]
        g.token    = token
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════════════
#  IMAP monitor (runs in background thread per user)
# ══════════════════════════════════════════════════════════════════════
import imaplib, email as _email_lib, time
from email.header import decode_header as _dh
from html.parser import HTMLParser

class _HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self._p = []
    def handle_data(self, d):
        self._p.append(d)
    def get_text(self):
        return " ".join(self._p)

def _strip_html(html):
    p = _HTMLStripper()
    try:
        p.feed(html)
        return p.get_text()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)

def _decode_str(value):
    if value is None: return ""
    parts = _dh(value)
    result = []
    for part, enc in parts:
        if isinstance(part, bytes):
            result.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            result.append(str(part))
    return " ".join(result)

def _extract_body(msg):
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition", ""))
            if "attachment" in disp: continue
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if not payload: continue
                text = payload.decode(charset, errors="replace")
                if ctype == "text/plain": plain += text
                elif ctype == "text/html": html  += text
            except Exception: pass
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html": html = text
                else: plain = text
        except Exception: pass
    body = plain.strip() or _strip_html(html).strip()
    return body[:4000]

def _get_mid(msg):
    mid = msg.get("Message-ID", "").strip()
    if mid: return mid
    return "|".join([msg.get("From",""), msg.get("Date",""), msg.get("Subject","")])

# ── Per-user monitor state ──────────────────────────────────────────────
monitor_state = {}
monitor_lock  = threading.Lock()

def _monitor_thread(username, gmail_address, app_password, stop_event):
    """Background IMAP polling loop for one user."""
    seen_ids = set()
    backoff  = 15

    def _log(msg):
        print(f"  [monitor:{username}] {msg}", flush=True)

    with monitor_lock:
        monitor_state[username]["status"]     = "running"
        monitor_state[username]["last_error"] = ""

    while not stop_event.is_set():
        mail = None
        try:
            _log("Connecting to Gmail IMAP...")
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(gmail_address, app_password)
            _log("Connected ✓")
            backoff = 15

            poll = 0
            while not stop_event.is_set():
                if poll % 10 == 0 and poll > 0:
                    try: mail.noop()
                    except Exception: raise ConnectionError("NOOP failed")

                try:
                    mail.select("INBOX")
                    _, data = mail.search(None, "UNSEEN")
                    imap_ids = data[0].split()

                    for iid in imap_ids:
                        if stop_event.is_set(): break
                        try:
                            status, msg_data = mail.fetch(iid, "(RFC822)")
                            if status != "OK" or not msg_data or msg_data[0] is None:
                                continue
                            raw = msg_data[0][1]
                            if not isinstance(raw, bytes): continue

                            msg     = _email_lib.message_from_bytes(raw)
                            mid     = _get_mid(msg)
                            if mid in seen_ids: continue
                            seen_ids.add(mid)

                            sender  = _decode_str(msg.get("From",    ""))
                            subject = _decode_str(msg.get("Subject", "(no subject)"))
                            body    = _extract_body(msg)
                            links   = "\n".join(re.findall(r"https?://[^\s<>\"']+", body))

                            result = analyze_email(sender, subject, body, links, "")
                            risk   = result.get("risk", "low")

                            entry = {
                                "time":       datetime.now().strftime("%H:%M:%S"),
                                "date":       datetime.now().strftime("%d %b %Y"),
                                "sender":     sender[:80],
                                "subject":    subject[:100],
                                "risk":       risk,
                                "risk_score": result.get("risk_score", 0),
                                "threats":    [t["label"] for t in result.get("threats", [])],
                                "source":     "monitor",
                                "user":       username,
                            }
                            _save_scan(entry)
                            if not MONGO_READY:
                                _increment_fallback_stats(risk)

                            with monitor_lock:
                                monitor_state[username]["emails_scanned"] += 1

                            _log(f"{risk.upper()} ({result.get('risk_score',0)}/100) — {subject[:50]}")

                        except Exception as e:
                            _log(f"Error on message: {e}")
                            continue

                except imaplib.IMAP4.abort as e:
                    raise ConnectionError(f"IMAP abort: {e}")
                except Exception as e:
                    _log(f"Inbox check error: {e}")

                stop_event.wait(30)
                poll += 1

        except ConnectionError as e:
            _log(f"Connection lost: {e}. Retry in {backoff}s")
            with monitor_lock:
                monitor_state[username]["last_error"] = str(e)
            stop_event.wait(backoff)
            backoff = min(backoff * 2, 120)

        except imaplib.IMAP4.error as e:
            err = f"IMAP auth error: {e}"
            _log(err)
            with monitor_lock:
                monitor_state[username]["status"]    = "error"
                monitor_state[username]["last_error"] = err
            break

        except Exception as e:
            _log(f"Unexpected: {e}. Retry in {backoff}s")
            with monitor_lock:
                monitor_state[username]["last_error"] = str(e)
            stop_event.wait(backoff)
            backoff = min(backoff * 2, 120)

        finally:
            if mail:
                try: mail.logout()
                except Exception: pass

    with monitor_lock:
        if monitor_state.get(username, {}).get("status") != "error":
            monitor_state[username]["status"] = "stopped"
    _log("Monitor stopped.")


# ══════════════════════════════════════════════════════════════════════
#  Analysis engine (ML + rules)
# ══════════════════════════════════════════════════════════════════════
def _ml_score(text):
    if not ML_READY or not text.strip(): return 0.5, 0.0
    cleaned = _clean(text)
    vec     = _vec.transform([cleaned])
    prob    = float(_clf.predict_proba(vec)[0][1])
    conf    = abs(prob - 0.5) * 2
    return prob, conf

def _rule_score(sender, subject, body, links, headers):
    score, threats, link_results, explanations = 0, [], [], []
    sl = sender.lower()
    if re.search(r'paypa[l1]|amaz[o0]n|g[o0]{2}gle|micr[o0]s[o0]ft|app[l1]e|netf[l1]ix|faceb[o0]{2}k', sl):
        score += 35
        threats.append({"label": "Spoofed sender domain", "type": "danger"})
        explanations.append("Sender mimics a well-known brand via character substitution.")
    if re.search(r'\.(xyz|tk|ml|ga|cf|top|loan|work|click|gq)$', sl):
        score += 20
        threats.append({"label": "Suspicious TLD", "type": "danger"})
        explanations.append("Sender domain uses a TLD common in phishing.")
    if "reply-to" in headers.lower():
        dom = sender.split("@")[-1] if "@" in sender else ""
        if dom and dom not in headers.lower():
            score += 15
            threats.append({"label": "Reply-To mismatch", "type": "warn"})
            explanations.append("Reply-To points to a different domain than the sender.")
    subjl = subject.lower()
    urgency = ["urgent","immediate","suspended","verify","confirm","unusual activity",
               "account locked","expires","action required","final notice","warning"]
    hits = [w for w in urgency if w in subjl]
    if hits:
        score += min(15 * len(hits), 30)
        threats.append({"label": "Urgency language in subject", "type": "warn"})
        explanations.append("Subject contains urgency trigger words: {}.".format(", ".join(hits[:3])))
    if len(subject) > 5 and sum(1 for c in subject if c.isupper()) > len(subject) * 0.5:
        score += 8
        threats.append({"label": "Excessive caps in subject", "type": "info"})
    bl = body.lower()
    phish_kw = ["click here","verify your account","sign in","update your information",
                "your account has been","limited time","winner","prize","congratulations",
                "free gift","bank details","password","credit card","ssn","social security"]
    bh = [w for w in phish_kw if w in bl]
    if len(bh) >= 2:
        score += min(10 * len(bh), 30)
        threats.append({"label": "Phishing keywords detected", "type": "warn"})
        explanations.append('Body has {} phishing phrases: "{}".'.format(len(bh), '", "'.join(bh[:3])))
    if re.search(r'<a\s+href', body, re.IGNORECASE):
        score += 10
        threats.append({"label": "HTML anchor tags in body", "type": "info"})
    link_list = [l.strip() for l in links.split("\n") if l.strip()]
    susp = False
    for url in link_list:
        u, status, reason = url.lower(), "safe", "OK"
        if re.search(r'bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|rebrand\.ly', u):
            status, reason = "warn", "URL shortener"; score += 12
        if re.search(r'paypa[l1]|amaz[o0]n|g[o0]{2}gle|micr[o0]s[o0]ft', u):
            dom = u.split("/")[2] if len(u.split("/")) > 2 else u
            if not re.search(r'\.(com|co\.uk|org)$', dom):
                status, reason = "danger", "Brand impersonation"; score += 25
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u):
            status, reason = "danger", "IP address URL"; score += 20
        if status == "safe" and re.search(r'login|signin|verify|account|update|secure|banking', u):
            status, reason = "warn", "Credential-harvesting path"; score += 10
        dom2 = u.split("/")[2] if len(u.split("/")) > 2 else u
        if re.search(r'\.(xyz|tk|ml|top|loan)$', dom2):
            status, reason = "danger", "Suspicious TLD"; score += 15
        link_results.append({"url": url, "status": status, "reason": reason})
        if status != "safe" and not susp:
            susp = True
            threats.append({"label": "Suspicious links detected", "type": "danger"})
            explanations.append("One or more links show URL obfuscation or brand impersonation.")
    return min(score, 100), threats, link_results, explanations

def analyze_email(sender, subject, body, links, headers):
    r_score, threats, link_results, explanations = _rule_score(sender, subject, body, links, headers)
    ml_prob, ml_conf = _ml_score(f"{sender} {subject} {body}")
    if ML_READY:
        final_score = int(min(round(ml_prob * 100 * 0.60 + r_score * 0.40), 100))
        if ml_prob >= 0.80 and ml_conf >= 0.6:
            threats.insert(0, {"label": "ML: high phishing probability", "type": "danger"})
            explanations.insert(0, f"ML confidence {ml_conf*100:.0f}% — phishing prob {ml_prob*100:.0f}%.")
        elif ml_prob <= 0.20 and ml_conf >= 0.6:
            threats.insert(0, {"label": "ML: likely safe email", "type": "info"})
            explanations.insert(0, f"ML confidence {ml_conf*100:.0f}% — safe prob {(1-ml_prob)*100:.0f}%.")
    else:
        final_score = r_score
    if final_score < 30:   risk, risk_score = "low",    max(final_score, 5)
    elif final_score < 65: risk, risk_score = "medium", final_score
    else:                  risk, risk_score = "high",   min(final_score, 98)
    if not threats:
        threats.append({"label": "No threats detected", "type": "info"})
        explanations.append("No phishing indicators found.")
    return {
        "risk": risk, "risk_score": risk_score,
        "threats": threats, "link_results": link_results,
        "explanations": explanations,
        "ml_prob": round(ml_prob * 100, 1) if ML_READY else None,
        "mode": "ML + rules" if ML_READY else "rules only",
    }


# ══════════════════════════════════════════════════════════════════════
#  Routes — Auth
# ══════════════════════════════════════════════════════════════════════
@app.route("/register", methods=["POST"])
def register():
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password", "")
    gmail    = (data.get("gmail") or "").strip()
    app_pw   = (data.get("app_password") or "").strip().replace(" ", "")

    if not username or not password or not gmail or not app_pw:
        return jsonify({"error": "All fields are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if "@" not in gmail:
        return jsonify({"error": "Invalid Gmail address"}), 400
    if len(app_pw) != 16:
        return jsonify({"error": "App password must be exactly 16 characters (no spaces)"}), 400
    if _user_exists(username):
        return jsonify({"error": "Username already taken"}), 409

    _save_user(username, {
        "password_hash": _hash_pw(password),
        "gmail":         gmail,
        "app_password":  app_pw,
        "created_at":    datetime.now().isoformat(),
    })
    return jsonify({"message": "Account created successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password", "")

    user = _get_user(username)
    if not user or user["password_hash"] != _hash_pw(password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = secrets.token_hex(32)
    sessions[token] = username
    return jsonify({"token": token, "username": username, "message": "Login successful"})


@app.route("/logout", methods=["POST"])
@require_auth
def logout():
    sessions.pop(g.token, None)
    return jsonify({"message": "Logged out"})


# ══════════════════════════════════════════════════════════════════════
#  Routes — Monitor control
# ══════════════════════════════════════════════════════════════════════
@app.route("/monitor/start", methods=["POST"])
@require_auth
def monitor_start():
    username = g.username
    user     = _get_user(username) or {}

    with monitor_lock:
        state = monitor_state.get(username, {})
        if state.get("status") == "running":
            return jsonify({"message": "Monitor already running", "status": "running"})

    gmail  = user.get("gmail", "")
    app_pw = user.get("app_password", "")
    if not gmail or not app_pw:
        return jsonify({"error": "Gmail credentials not found for this account"}), 400

    stop_event = threading.Event()
    t = threading.Thread(
        target=_monitor_thread,
        args=(username, gmail, app_pw, stop_event),
        daemon=True,
        name=f"monitor-{username}",
    )
    with monitor_lock:
        monitor_state[username] = {
            "thread":         t,
            "stop_event":     stop_event,
            "status":         "starting",
            "last_error":     "",
            "emails_scanned": 0,
            "started_at":     datetime.now().isoformat(),
        }
    t.start()
    return jsonify({"message": "Monitor started", "status": "starting"})


@app.route("/monitor/stop", methods=["POST"])
@require_auth
def monitor_stop():
    username = g.username
    with monitor_lock:
        state = monitor_state.get(username)
        if not state or state["status"] in ("stopped", "error"):
            return jsonify({"message": "Monitor not running", "status": "stopped"})
        state["stop_event"].set()
        state["status"] = "stopping"
    return jsonify({"message": "Monitor stopping...", "status": "stopping"})


@app.route("/monitor/status", methods=["GET"])
@require_auth
def monitor_status():
    username = g.username
    with monitor_lock:
        state = monitor_state.get(username, {})
    return jsonify({
        "status":         state.get("status", "stopped"),
        "emails_scanned": state.get("emails_scanned", 0),
        "last_error":     state.get("last_error", ""),
        "started_at":     state.get("started_at", None),
    })


# ══════════════════════════════════════════════════════════════════════
#  Routes — Existing + new scan fetch
# ══════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory(".", "login.html")

@app.route("/app")
def main_app():
    return send_from_directory(".", "index.html")

@app.route("/dashboard")
def dashboard():
    return send_from_directory(".", "Dashboard.html")


@app.route("/analyze", methods=["POST"])
@require_auth
def analyze():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body received"}), 400
    sender  = data.get("sender",  "")
    subject = data.get("subject", "")
    body    = data.get("body",    "")
    links   = data.get("links",   "")
    headers = data.get("headers", "")
    source  = data.get("source",  "manual")
    if not sender and not subject and not body:
        return jsonify({"error": "Provide at least sender, subject, or body"}), 400

    result = analyze_email(sender, subject, body, links, headers)
    entry  = {
        "time":       datetime.now().strftime("%H:%M:%S"),
        "date":       datetime.now().strftime("%d %b %Y"),
        "sender":     sender[:80],
        "subject":    subject[:100],
        "risk":       result["risk"],
        "risk_score": result["risk_score"],
        "threats":    [t["label"] for t in result["threats"]],
        "source":     source,
        "mode":       result["mode"],
        "user":       g.username,
    }
    _save_scan(entry)
    if not MONGO_READY:
        _increment_fallback_stats(result["risk"])

    return jsonify(result)


@app.route("/api/dashboard", methods=["GET"])
@require_auth
def api_dashboard():
    return jsonify({
        "stats":        _get_stats(),
        "scans":        _get_scans(200),
        "mongo_ready":  MONGO_READY,
    })


@app.route("/api/scans/<scan_id>", methods=["GET"])
@require_auth
def get_scan(scan_id):
    """Fetch a single scan document by MongoDB _id."""
    if not MONGO_READY:
        return jsonify({"error": "MongoDB not available"}), 503
    try:
        doc = _scans_col.find_one({"_id": ObjectId(scan_id)})
        if not doc:
            return jsonify({"error": "Scan not found"}), 404
        doc["_id"] = str(doc["_id"])
        if "created_at" in doc:
            doc["created_at"] = doc["created_at"].isoformat()
        return jsonify(doc)
    except InvalidId:
        return jsonify({"error": "Invalid scan ID"}), 400


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":      "ok",
        "ml_ready":    ML_READY,
        "mode":        "ML + rules" if ML_READY else "rules only",
        "mongo_ready": MONGO_READY,
        "mongo_uri":   MONGO_URI if MONGO_READY else None,
    })


if __name__ == "__main__":
    print("\n  PhishGuard v4  running:")
    print("  Login     -> http://localhost:5000")
    print("  App       -> http://localhost:5000/app")
    print("  Dashboard -> http://localhost:5000/dashboard")
    print(f"  ML mode   -> {'enabled' if ML_READY else 'disabled'}")
    print(f"  MongoDB   -> {'connected' if MONGO_READY else 'fallback (json/memory)'}\n")
    app.run(debug=True, port=5000)