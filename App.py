"""
PhishGuard – Flask API  (v5 – Full MongoDB persistence)
=======================================================
  • _to_python()  converts numpy scalars so MongoDB never rejects the doc
  • /analyze      saves ALL inputs + full result + interview fields
  • /analyze/interview  updates the SAME doc in-place via $set
  • /api/history  returns full per-user scan history from MongoDB
  • /health/db    quick write-test diagnostic
"""

from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
import re, os, json, logging, hashlib, secrets, threading
from datetime import datetime
from functools import wraps

# ── MongoDB ──────────────────────────────────────────────────────────────
try:
    from pymongo import MongoClient, DESCENDING
    from pymongo.errors import ConnectionFailure, OperationFailure
    from bson import ObjectId
    from bson.errors import InvalidId

    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    _mongo_client.admin.command("ping")
    _db        = _mongo_client["phishguard"]
    _users_col        = _db["users"]
    _scans_col        = _db["scans"]
    _manual_scans_col = _db["manual_scans"]

    _users_col.create_index("username", unique=True)
    _scans_col.create_index([("created_at", DESCENDING)])
    _scans_col.create_index("user")
    _scans_col.create_index("risk")
    _scans_col.create_index("source")
    _manual_scans_col.create_index([("created_at", DESCENDING)])
    _manual_scans_col.create_index("user")
    _manual_scans_col.create_index("risk")

    MONGO_READY = True
    print("  [MongoDB] Connected → phishguard database")

except Exception as _me:
    MONGO_READY = False
    _db = _users_col = _scans_col = _manual_scans_col = None
    print(f"  [MongoDB] Unavailable ({_me}) – falling back to in-memory")

from incident_report import send_incident_report, build_report_html

# ── Desktop notifications ────────────────────────────────────────────────
try:
    from plyer import notification as _plyer_notification
    PLYER_READY = True
except ImportError:
    PLYER_READY = False
    print("  [Notify] plyer not installed — pip install plyer  (desktop popups disabled)")

def _send_desktop_notification(title: str, message: str) -> None:
    """Fire a desktop popup. Silently skips if plyer is unavailable."""
    if not PLYER_READY:
        return
    try:
        _plyer_notification.notify(
            title=title,
            message=message,
            app_name="PhishGuard",
            timeout=10,
        )
    except Exception as e:
        print(f"  [Notify] Desktop notification failed: {e}", flush=True)

# ── IT Team email config ─────────────────────────────────────────────────
IT_EMAIL = os.environ.get("IT_EMAIL", "it-team@yourcompany.com")


# ── ML ───────────────────────────────────────────────────────────────────
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

# ── App ──────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=".")
CORS(app, supports_credentials=True)
logging.basicConfig(level=logging.INFO)

from collections import deque
_fallback_scan_log = deque(maxlen=200)
_fallback_stats    = {"total": 0, "high": 0, "medium": 0, "low": 0}

# ── numpy-safe BSON converter ────────────────────────────────────────────
try:
    _NP_INT   = np.integer
    _NP_FLOAT = np.floating
    _NP_ARR   = np.ndarray
    _NP_OK    = True
except Exception:
    _NP_OK    = False

def _to_python(obj):
    """Recursively strip numpy / nan / inf so MongoDB never rejects a doc."""
    if _NP_OK:
        if isinstance(obj, _NP_INT):   return int(obj)
        if isinstance(obj, _NP_FLOAT): return float(obj)
        if isinstance(obj, _NP_ARR):   return [_to_python(i) for i in obj.tolist()]
    if isinstance(obj, dict):
        return {str(k): _to_python(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_python(i) for i in obj]
    if isinstance(obj, float) and (obj != obj or obj in (float('inf'), float('-inf'))):
        return None
    return obj

# ── User helpers ─────────────────────────────────────────────────────────
USERS_FILE = "users.json"

def _load_users():
    if MONGO_READY:
        try:
            docs = list(_users_col.find({}, {"_id": 0}))
            return {d["username"]: d for d in docs}
        except Exception: pass
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f: return json.load(f)
        except Exception: pass
    return {}

def _get_user(username):
    if MONGO_READY:
        try: return _users_col.find_one({"username": username}, {"_id": 0})
        except Exception: pass
    return _load_users().get(username)

def _save_user(username, doc):
    if MONGO_READY:
        try:
            doc["username"] = username
            _users_col.update_one({"username": username}, {"$set": doc}, upsert=True)
            return
        except Exception as e: print(f"  [MongoDB] _save_user error: {e}")
    users = _load_users()
    users[username] = doc
    with open(USERS_FILE, "w") as f: json.dump(users, f, indent=2)

def _user_exists(username):
    if MONGO_READY:
        try: return _users_col.count_documents({"username": username}) > 0
        except Exception: pass
    return username in _load_users()

def _hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ── Scan helpers ─────────────────────────────────────────────────────────

def _save_scan(entry: dict) -> str:
    """Sanitise and persist a scan. Returns the _id string."""
    if MONGO_READY:
        try:
            doc = _to_python(entry)
            doc["created_at"] = datetime.utcnow()
            result = _scans_col.insert_one(doc)
            scan_id = str(result.inserted_id)
            entry["_id"] = scan_id
            print(f"  [MongoDB] ✓ Scan saved  source={entry.get('source')}  _id={scan_id}", flush=True)
            return scan_id
        except Exception as e:
            print(f"  [MongoDB] ✗ _save_scan FAILED: {e}", flush=True)
    import uuid
    scan_id = str(uuid.uuid4())
    entry["_id"] = scan_id
    _fallback_scan_log.appendleft(_to_python(entry))
    print(f"  [Fallback] Scan stored in-memory  _id={scan_id}", flush=True)
    return scan_id

def _save_manual_scan(entry: dict) -> str:
    """Save to the dedicated manual_scans collection."""
    if MONGO_READY:
        try:
            doc = _to_python(entry)
            doc["created_at"] = datetime.utcnow()
            result = _manual_scans_col.insert_one(doc)
            scan_id = str(result.inserted_id)
            entry["_id"] = scan_id
            print(f"  [MongoDB] ✓ Manual scan saved  _id={scan_id}", flush=True)
            return scan_id
        except Exception as e:
            print(f"  [MongoDB] ✗ _save_manual_scan FAILED: {e}", flush=True)
    import uuid
    scan_id = str(uuid.uuid4())
    entry["_id"] = scan_id
    _fallback_scan_log.appendleft(_to_python(entry))
    return scan_id


def _update_manual_scan(scan_id: str, fields: dict):
    """Update a manual_scans document in-place."""
    if MONGO_READY:
        try:
            _manual_scans_col.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": _to_python(fields)}
            )
            print(f"  [MongoDB] ✓ Manual scan updated  _id={scan_id}", flush=True)
            return
        except Exception as e:
            print(f"  [MongoDB] ✗ _update_manual_scan FAILED: {e}", flush=True)
    for doc in _fallback_scan_log:
        if doc.get("_id") == scan_id:
            doc.update(_to_python(fields)); break


def _get_manual_history(username: str, limit: int = 100):
    """Return full manual scan history for a user from manual_scans collection."""
    if MONGO_READY:
        try:
            cursor = _manual_scans_col.find(
                {"user": username},
                {"_id":1,"time":1,"date":1,"created_at":1,
                 "sender":1,"subject":1,"body":1,"links":1,"headers":1,
                 "risk":1,"risk_score":1,"threats":1,"explanations":1,
                 "link_results":1,"ml_prob":1,"mode":1,"source":1,
                 "interview_answers":1,"interview_score":1,
                 "base_score":1,"score_breakdown":1,"interview_complete":1}
            ).sort("created_at", DESCENDING).limit(limit)
            docs = []
            for d in cursor:
                d["_id"] = str(d["_id"])
                if "created_at" in d: d["created_at"] = d["created_at"].isoformat()
                docs.append(d)
            return docs
        except Exception as e:
            print(f"  [MongoDB] _get_manual_history error: {e}")
    return [d for d in _fallback_scan_log if d.get("user") == username][:limit]


def _update_scan(scan_id: str, fields: dict):
    """Update existing scan document in-place."""
    if MONGO_READY:
        try:
            _scans_col.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": _to_python(fields)}
            )
            print(f"  [MongoDB] ✓ Scan updated  _id={scan_id}", flush=True)
            return
        except Exception as e:
            print(f"  [MongoDB] ✗ _update_scan FAILED: {e}", flush=True)
    for doc in _fallback_scan_log:
        if doc.get("_id") == scan_id:
            doc.update(_to_python(fields)); break

def _get_scans(limit=200):
    if MONGO_READY:
        try:
            cursor = _scans_col.find(
                {}, {"_id":1,"time":1,"date":1,"sender":1,"subject":1,
                     "risk":1,"risk_score":1,"threats":1,"source":1,"mode":1,"user":1}
            ).sort("created_at", DESCENDING).limit(limit)
            docs = []
            for d in cursor:
                d["_id"] = str(d["_id"]); docs.append(d)
            return docs
        except Exception as e: print(f"  [MongoDB] _get_scans error: {e}")
    return list(_fallback_scan_log)

def _get_history_for_user(username, limit=100):
    if MONGO_READY:
        try:
            cursor = _scans_col.find(
                {"user": username},
                {"_id":1,"time":1,"date":1,"created_at":1,
                 "sender":1,"subject":1,"body":1,"links":1,"headers":1,
                 "risk":1,"risk_score":1,"threats":1,"explanations":1,
                 "link_results":1,"ml_prob":1,"mode":1,"source":1,
                 "interview_answers":1,"interview_score":1,
                 "base_score":1,"score_breakdown":1,"interview_complete":1}
            ).sort("created_at", DESCENDING).limit(limit)
            docs = []
            for d in cursor:
                d["_id"] = str(d["_id"])
                if "created_at" in d: d["created_at"] = d["created_at"].isoformat()
                docs.append(d)
            return docs
        except Exception as e: print(f"  [MongoDB] _get_history error: {e}")
    return [d for d in _fallback_scan_log if d.get("user") == username][:limit]

def _get_stats():
    if MONGO_READY:
        try:
            agg = {d["_id"]: d["count"] for d in _scans_col.aggregate([
                {"$group": {"_id": "$risk", "count": {"$sum": 1}}}
            ])}
            total = sum(agg.values())
            return {"total":total,"high":agg.get("high",0),"medium":agg.get("medium",0),"low":agg.get("low",0)}
        except Exception as e: print(f"  [MongoDB] _get_stats error: {e}")
    return dict(_fallback_stats)

def _increment_fallback_stats(risk):
    _fallback_stats["total"] += 1
    _fallback_stats[risk]    += 1

# ── Sessions ─────────────────────────────────────────────────────────────
sessions = {}

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

# ── IMAP monitor ─────────────────────────────────────────────────────────
import imaplib, email as _email_lib, time
from email.header import decode_header as _dh
from html.parser import HTMLParser

class _HTMLStripper(HTMLParser):
    def __init__(self): super().__init__(); self._p = []
    def handle_data(self, d): self._p.append(d)
    def get_text(self): return " ".join(self._p)

def _strip_html(html):
    p = _HTMLStripper()
    try: p.feed(html); return p.get_text()
    except Exception: return re.sub(r"<[^>]+>", " ", html)

def _decode_str(value):
    if value is None: return ""
    parts = _dh(value); result = []
    for part, enc in parts:
        if isinstance(part, bytes): result.append(part.decode(enc or "utf-8", errors="replace"))
        else: result.append(str(part))
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
    return (plain.strip() or _strip_html(html).strip())[:4000]

def _get_mid(msg):
    mid = msg.get("Message-ID", "").strip()
    if mid: return mid
    return "|".join([msg.get("From",""), msg.get("Date",""), msg.get("Subject","")])

monitor_state = {}
monitor_lock  = threading.Lock()

def _monitor_thread(username, gmail_address, app_password, stop_event):
    seen_ids = set(); backoff = 15
    def _log(msg): print(f"  [monitor:{username}] {msg}", flush=True)
    with monitor_lock:
        monitor_state[username]["status"] = "running"
        monitor_state[username]["last_error"] = ""
    while not stop_event.is_set():
        mail = None
        try:
            _log("Connecting to Gmail IMAP...")
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(gmail_address, app_password)
            _log("Connected ✓"); backoff = 15
            poll = 0
            while not stop_event.is_set():
                if poll % 10 == 0 and poll > 0:
                    try: mail.noop()
                    except Exception: raise ConnectionError("NOOP failed")
                try:
                    mail.select("INBOX")
                    _, data = mail.search(None, "UNSEEN")
                    for iid in data[0].split():
                        if stop_event.is_set(): break
                        try:
                            status, msg_data = mail.fetch(iid, "(RFC822)")
                            if status != "OK" or not msg_data or msg_data[0] is None: continue
                            raw = msg_data[0][1]
                            if not isinstance(raw, bytes): continue
                            msg     = _email_lib.message_from_bytes(raw)
                            mid     = _get_mid(msg)
                            if mid in seen_ids: continue
                            seen_ids.add(mid)
                            sender  = _decode_str(msg.get("From", ""))
                            subject = _decode_str(msg.get("Subject", "(no subject)"))
                            body    = _extract_body(msg)
                            links   = "\n".join(re.findall(r"https?://[^\s<>\"']+", body))
                            result  = analyze_email(sender, subject, body, links, "")
                            risk    = result.get("risk", "low")
                            entry = {
                                "time":               datetime.now().strftime("%H:%M:%S"),
                                "date":               datetime.now().strftime("%d %b %Y"),
                                "sender":             sender[:80],
                                "subject":            subject[:100],
                                "body":               body[:2000],
                                "links":              links[:1000],
                                "headers":            "",
                                "risk":               risk,
                                "risk_score":         result.get("risk_score", 0),
                                "threats":            result.get("threats", []),
                                "explanations":       result.get("explanations", []),
                                "link_results":       result.get("link_results", []),
                                "ml_prob":            result.get("ml_prob"),
                                "source":             "monitor",
                                "mode":               result.get("mode", "rules only"),
                                "user":               username,
                                "interview_complete": False,
                                "interview_answers":  {},
                                "interview_score":    0,
                                "base_score":         result.get("risk_score", 0),
                                "score_breakdown":    None,
                            }
                            _save_scan(entry)
                            if not MONGO_READY: _increment_fallback_stats(risk)
                            with monitor_lock: monitor_state[username]["emails_scanned"] += 1
                            _log(f"{risk.upper()} ({result.get('risk_score',0)}/100) — {subject[:50]}")
                            if risk == "high":
                                # ── Desktop popup notification ────────────────
                                risk_score = result.get("risk_score", 0)
                                threat_labels = ", ".join(
                                    (t["label"] if isinstance(t, dict) else str(t))
                                    for t in result.get("threats", [])[:2]
                                )
                                notif_title   = f"⚠ PhishGuard: HIGH RISK email detected"
                                notif_message = (
                                    f"Score: {risk_score}/100\n"
                                    f"From: {sender[:60]}\n"
                                    f"Subject: {subject[:60]}\n"
                                    f"{threat_labels}"
                                )
                                _send_desktop_notification(notif_title, notif_message)
                                _log("[!] Desktop notification sent")
                                user_doc = _get_user(username) or {}
                                report_entry = dict(entry)
                                report_entry["domain_results"] = result.get("domain_results", [])
                                send_incident_report(
                                    scan             = report_entry,
                                    reporter         = username,
                                    gmail_address    = user_doc.get("gmail", ""),
                                    app_password     = user_doc.get("app_password", ""),
                                    it_email         = IT_EMAIL,
                                    scans_col        = _scans_col,
                                    manual_scans_col = _manual_scans_col,
                                )

                        except Exception as e: _log(f"Error on message: {e}"); continue
                except imaplib.IMAP4.abort as e: raise ConnectionError(f"IMAP abort: {e}")
                except Exception as e: _log(f"Inbox check error: {e}")
                stop_event.wait(30); poll += 1
        except ConnectionError as e:
            _log(f"Connection lost: {e}. Retry in {backoff}s")
            with monitor_lock: monitor_state[username]["last_error"] = str(e)
            stop_event.wait(backoff); backoff = min(backoff * 2, 120)
        except imaplib.IMAP4.error as e:
            err = f"IMAP auth error: {e}"; _log(err)
            with monitor_lock:
                monitor_state[username]["status"] = "error"
                monitor_state[username]["last_error"] = err
            break
        except Exception as e:
            _log(f"Unexpected: {e}. Retry in {backoff}s")
            with monitor_lock: monitor_state[username]["last_error"] = str(e)
            stop_event.wait(backoff); backoff = min(backoff * 2, 120)
        finally:
            if mail:
                try: mail.logout()
                except Exception: pass
    with monitor_lock:
        if monitor_state.get(username, {}).get("status") != "error":
            monitor_state[username]["status"] = "stopped"
    _log("Monitor stopped.")

# ── Domain validation engine ─────────────────────────────────────────────
import socket
import threading as _threading

# Cache results so repeated domains don't cause extra DNS calls
_domain_cache = {}
_domain_cache_lock = _threading.Lock()

def _extract_domain(value: str) -> str:
    """Pull the bare domain from a URL or email address."""
    value = value.strip().lower()
    # URL
    if value.startswith("http"):
        parts = value.split("/")
        return parts[2] if len(parts) > 2 else value
    # Email  user@domain
    if "@" in value:
        return value.split("@")[-1].split(">")[0].strip()
    return value


def _dns_check(domain: str) -> dict:
    """
    Check whether a domain resolves (A record) and has mail records (MX).
    Returns a dict with keys: exists, has_mx, ip.
    Results are cached to avoid repeat lookups in the same request.
    """
    domain = domain.strip().rstrip(".")
    if not domain or len(domain) < 4:
        return {"exists": False, "has_mx": False, "ip": None}

    with _domain_cache_lock:
        if domain in _domain_cache:
            return _domain_cache[domain]

    result = {"exists": False, "has_mx": False, "ip": None}
    try:
        ip = socket.gethostbyname(domain)
        result["exists"] = True
        result["ip"]     = ip
    except Exception:
        pass

    # MX check via socket (no external lib needed)
    try:
        import dns.resolver  # optional – dnspython
        answers = dns.resolver.resolve(domain, "MX", lifetime=2)
        result["has_mx"] = len(answers) > 0
    except Exception:
        # dnspython not installed or no MX — not critical
        result["has_mx"] = result["exists"]   # assume MX if domain resolves

    with _domain_cache_lock:
        _domain_cache[domain] = result
    return result


def _whois_age_days(domain: str) -> int | None:
    """
    Return the domain age in days.
    Tries python-whois then whois package — returns None if neither available.
    """
    w_obj = None
    try:
        # try python-whois (pip install python-whois)
        import pythonwhois as _pw
        w_obj = _pw.get_whois(domain)
        created = w_obj.get("creation_date", [None])[0] if w_obj else None
    except Exception:
        pass

    if w_obj is None:
        try:
            # try whois (pip install whois)
            import whois as _w
            w_obj = _w.whois(domain)
            created = w_obj.creation_date if w_obj else None
            if isinstance(created, list): created = created[0]
        except Exception:
            return None

    try:
        if created is None: return None
        from datetime import timezone
        if hasattr(created, "tzinfo"):
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created).days
        return age
    except Exception:
        return None


def _domain_validation_score(sender: str, links: str) -> tuple[int, list, list]:
    """
    Run DNS + WHOIS checks on the sender domain and all link domains.
    Returns (score_delta, extra_threats, extra_explanations).
    Uses a 3-second timeout per domain via threading so slow DNS never
    blocks the request for more than ~6 seconds total.
    """
    delta        = 0
    threats      = []
    explanations = []
    domain_results = []

    # Collect all domains to check
    domains_to_check = []
    sender_domain = _extract_domain(sender)
    if sender_domain:
        domains_to_check.append(("sender", sender_domain))

    for url in [l.strip() for l in links.split("\n") if l.strip()]:
        d = _extract_domain(url)
        if d and d not in [x[1] for x in domains_to_check]:
            domains_to_check.append(("link", d))

    def _check_one(kind, domain, results_list):
        dns = _dns_check(domain)
        age = None
        if dns["exists"]:
            age = _whois_age_days(domain)
        results_list.append((kind, domain, dns, age))

    # Run all checks in parallel with 4-second cap
    threads = []
    raw_results = []
    for kind, domain in domains_to_check[:6]:   # cap at 6 domains
        t = _threading.Thread(target=_check_one, args=(kind, domain, raw_results), daemon=True)
        threads.append(t); t.start()
    for t in threads:
        t.join(timeout=4)

    for kind, domain, dns, age in raw_results:
        entry = {"domain": domain, "kind": kind,
                 "exists": dns["exists"], "ip": dns["ip"],
                 "has_mx": dns["has_mx"], "age_days": age}
        domain_results.append(entry)

        if kind == "sender":
            if not dns["exists"]:
                delta += 30
                threats.append({"label": "Sender domain does not exist (DNS)", "type": "danger"})
                explanations.append(f"Sender domain '{domain}' has no DNS A record — likely a fake/spoofed domain.")
            elif age is not None and age < 30:
                delta += 25
                threats.append({"label": f"Sender domain very new ({age}d old)", "type": "danger"})
                explanations.append(f"Sender domain '{domain}' was registered only {age} days ago — newly registered domains are a strong phishing indicator.")
            elif age is not None and age < 180:
                delta += 12
                threats.append({"label": f"Sender domain recently registered ({age}d)", "type": "warn"})
                explanations.append(f"Sender domain '{domain}' is only {age} days old, which is suspicious.")

        elif kind == "link":
            if not dns["exists"]:
                delta += 20
                threats.append({"label": f"Link domain does not resolve: {domain}", "type": "danger"})
                explanations.append(f"Link domain '{domain}' has no DNS record — possible dead or fake domain.")
            elif age is not None and age < 30:
                delta += 20
                threats.append({"label": f"Link domain very new ({age}d): {domain}", "type": "danger"})
                explanations.append(f"Link domain '{domain}' registered {age} days ago — newly created domains are commonly used in phishing campaigns.")
            elif age is not None and age < 180:
                delta += 8
                threats.append({"label": f"Link domain recently registered ({age}d)", "type": "warn"})
                explanations.append(f"Link domain '{domain}' is {age} days old.")

    return min(delta, 40), threats, explanations, domain_results


# ── Analysis engine ───────────────────────────────────────────────────────
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
        score += 35; threats.append({"label": "Spoofed sender domain", "type": "danger"})
        explanations.append("Sender mimics a well-known brand via character substitution.")
    if re.search(r'\.(xyz|tk|ml|ga|cf|top|loan|work|click|gq)$', sl):
        score += 20; threats.append({"label": "Suspicious TLD", "type": "danger"})
        explanations.append("Sender domain uses a TLD common in phishing.")
    if "reply-to" in headers.lower():
        dom = sender.split("@")[-1] if "@" in sender else ""
        if dom and dom not in headers.lower():
            score += 15; threats.append({"label": "Reply-To mismatch", "type": "warn"})
            explanations.append("Reply-To points to a different domain than the sender.")
    subjl = subject.lower()
    urgency = ["urgent","immediate","suspended","verify","confirm","unusual activity",
               "account locked","expires","action required","final notice","warning"]
    hits = [w for w in urgency if w in subjl]
    if hits:
        score += min(15 * len(hits), 30); threats.append({"label": "Urgency language in subject", "type": "warn"})
        explanations.append("Subject contains urgency trigger words: {}.".format(", ".join(hits[:3])))
    if len(subject) > 5 and sum(1 for c in subject if c.isupper()) > len(subject) * 0.5:
        score += 8; threats.append({"label": "Excessive caps in subject", "type": "info"})
    bl = body.lower()
    phish_kw = ["click here","verify your account","sign in","update your information",
                "your account has been","limited time","winner","prize","congratulations",
                "free gift","bank details","password","credit card","ssn","social security"]
    bh = [w for w in phish_kw if w in bl]
    if len(bh) >= 2:
        score += min(10 * len(bh), 30); threats.append({"label": "Phishing keywords detected", "type": "warn"})
        explanations.append('Body has {} phishing phrases: "{}".'.format(len(bh), '", "'.join(bh[:3])))
    if re.search(r'<a\s+href', body, re.IGNORECASE):
        score += 10; threats.append({"label": "HTML anchor tags in body", "type": "info"})
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
            susp = True; threats.append({"label": "Suspicious links detected", "type": "danger"})
            explanations.append("One or more links show URL obfuscation or brand impersonation.")
    return min(score, 100), threats, link_results, explanations

def analyze_email(sender, subject, body, links, headers):
    r_score, threats, link_results, explanations = _rule_score(sender, subject, body, links, headers)

    # ── Domain validation (DNS + WHOIS) ──────────────────────────────────
    d_score, d_threats, d_explanations, domain_results = _domain_validation_score(sender, links)
    threats      = d_threats + threats
    explanations = d_explanations + explanations

    ml_prob, ml_conf = _ml_score(f"{sender} {subject} {body}")
    if ML_READY:
        # Weighted blend: 50% ML + 30% rules + 20% domain validation
        raw = ml_prob * 100 * 0.50 + r_score * 0.30 + (r_score + d_score) * 0.20
        final_score = int(min(round(raw), 100))
        if ml_prob >= 0.80 and ml_conf >= 0.6:
            threats.insert(0, {"label": "ML: high phishing probability", "type": "danger"})
            explanations.insert(0, f"ML confidence {ml_conf*100:.0f}% — phishing prob {ml_prob*100:.0f}%.")
        elif ml_prob <= 0.20 and ml_conf >= 0.6:
            threats.insert(0, {"label": "ML: likely safe email", "type": "info"})
            explanations.insert(0, f"ML confidence {ml_conf*100:.0f}% — safe prob {(1-ml_prob)*100:.0f}%.")
    else:
        # Rules + domain validation only
        final_score = min(r_score + d_score, 100)

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
        "mode": "ML + rules + domain validation" if ML_READY else "rules + domain validation",
        "domain_results": domain_results,
    }

# ── Interview scoring ─────────────────────────────────────────────────────
def _interview_score(answers):
    delta = 0; threats = []; explanations = []
    q1 = answers.get("q1", "")
    if q1 == "no":
        delta += 20; threats.append({"label": "Unsolicited email", "type": "warn"})
        explanations.append("User did not expect this email — unsolicited contact is a common phishing vector.")
    elif q1 == "not_sure": delta += 8
    q2 = answers.get("q2", "")
    if q2 == "no":
        delta += 20; threats.append({"label": "Unrecognised sender", "type": "warn"})
        explanations.append("User does not recognise the sender, increasing likelihood of a spoofed identity.")
    elif q2 == "not_sure": delta += 8
    q3 = answers.get("q3", "")
    if q3 == "yes_link":
        delta += 15; threats.append({"label": "User prompted to click link", "type": "danger"})
        explanations.append("Email prompts the user to click a link — a hallmark of credential-harvesting attacks.")
    elif q3 == "yes_attachment":
        delta += 18; threats.append({"label": "User prompted to open attachment", "type": "danger"})
        explanations.append("Email prompts the user to open an attachment, which may carry malware.")
    elif q3 == "yes_info":
        delta += 20; threats.append({"label": "Personal information requested", "type": "danger"})
        explanations.append("Email requests personal or sensitive information from the user.")
    elif q3 == "multiple":
        delta += 25; threats.append({"label": "Multiple action requests", "type": "danger"})
        explanations.append("Email requests multiple types of user action simultaneously — a strong phishing signal.")
    q4 = answers.get("q4", "")
    if q4 == "yes":
        delta += 15; threats.append({"label": "User perceives urgency/fear tactics", "type": "warn"})
        explanations.append("User reports the email creates urgency or fear — a common social-engineering technique.")
    elif q4 == "not_sure": delta += 5
    q5 = answers.get("q5", "")
    if q5 == "yes":
        delta += 10; threats.append({"label": "Part of a suspected campaign", "type": "warn"})
        explanations.append("User has received similar emails recently, suggesting a targeted phishing campaign.")
    elif q5 == "not_sure": delta += 3
    return delta, threats, explanations

# ══════════════════════════════════════════════════════════════════════
#  Incident report engine
# ══════════════════════════════════════════════════════════════════════
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text       import MIMEText
from email.mime.base       import MIMEBase
from email                 import encoders
import io

# ══════════════════════════════════════════════════════════════════════
#  Auth routes
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
        "password_hash": _hash_pw(password), "gmail": gmail,
        "app_password": app_pw, "created_at": datetime.now().isoformat(),
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
#  Monitor routes
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
    t = threading.Thread(target=_monitor_thread, args=(username, gmail, app_pw, stop_event),
                         daemon=True, name=f"monitor-{username}")
    with monitor_lock:
        monitor_state[username] = {
            "thread": t, "stop_event": stop_event, "status": "starting",
            "last_error": "", "emails_scanned": 0, "started_at": datetime.now().isoformat(),
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
#  Core routes
# ══════════════════════════════════════════════════════════════════════
@app.route("/")
def index(): return send_from_directory(".", "login.html")

@app.route("/app")
def main_app(): return send_from_directory(".", "index.html")

@app.route("/dashboard")
def dashboard(): return send_from_directory(".", "Dashboard.html")


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
    if not sender and not subject and not body:
        return jsonify({"error": "Provide at least sender, subject, or body"}), 400

    print(f"  [/analyze] user={g.username}  subject={subject[:50]!r}", flush=True)

    result = analyze_email(sender, subject, body, links, headers)

    entry = {
        "time":               datetime.now().strftime("%H:%M:%S"),
        "date":               datetime.now().strftime("%d %b %Y"),
        "sender":             sender[:80],
        "subject":            subject[:100],
        "body":               body[:4000],
        "links":              links[:2000],
        "headers":            headers[:1000],
        "risk":               result["risk"],
        "risk_score":         result["risk_score"],
        "threats":            result["threats"],
        "explanations":       result["explanations"],
        "link_results":       result["link_results"],
        "ml_prob":            result.get("ml_prob"),
        "domain_results":     result.get("domain_results", []),
        "source":             "manual",
        "mode":               result["mode"],
        "user":               g.username,
        "interview_complete": False,
        "interview_answers":  {},
        "interview_score":    0,
        "base_score":         result["risk_score"],
        "score_breakdown":    None,
    }

    scan_id = _save_manual_scan(entry)
    if not MONGO_READY:
        _increment_fallback_stats(result["risk"])

    result["scan_id"] = scan_id
    return jsonify(result)


@app.route("/analyze/interview", methods=["POST"])
@require_auth
def analyze_interview():
    data    = request.get_json() or {}
    base    = data.get("base_result", {})
    answers = data.get("answers", {})
    scan_id = data.get("scan_id", "")

    if not base:
        return jsonify({"error": "base_result is required"}), 400

    base_score             = base.get("risk_score", 0)
    interview_delta, extra_threats, extra_explanations = _interview_score(answers)
    interview_contribution = min(interview_delta, 40)

    final_score = int(min(round(base_score * 0.70 + (base_score + interview_contribution) * 0.30), 100))
    final_score = max(final_score, 1)
    if final_score < 30:   risk = "low";    final_score = max(final_score, 5)
    elif final_score < 65: risk = "medium"
    else:                  risk = "high";   final_score = min(final_score, 98)

    merged_threats = extra_threats + [
        t for t in base.get("threats", []) if t.get("label") != "No threats detected"
    ] or [{"label": "No threats detected", "type": "info"}]

    merged_explanations = extra_explanations + [
        e for e in base.get("explanations", []) if "No phishing indicators" not in e
    ] or ["No phishing indicators found."]

    score_breakdown = {
        "ml_rules_score":  base_score,
        "interview_delta": interview_contribution,
        "final_score":     final_score,
        "weights":         "70% ML/rules + 30% interview",
    }

    update_fields = {
        "risk":               risk,
        "risk_score":         final_score,
        "threats":            merged_threats,
        "explanations":       merged_explanations,
        "interview_complete": True,
        "interview_answers":  answers,
        "interview_score":    interview_contribution,
        "base_score":         base_score,
        "score_breakdown":    score_breakdown,
        "source":             "manual+interview",
        "mode":               base.get("mode", "rules only") + " + interview",
    }

    if scan_id:
        _update_manual_scan(scan_id, update_fields)
    else:
        # No scan_id — save as new doc (shouldn't happen normally)
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "date": datetime.now().strftime("%d %b %Y"),
            "sender": base.get("_sender", "")[:80],
            "subject": base.get("_subject", "")[:100],
            "link_results": base.get("link_results", []),
            "ml_prob": base.get("ml_prob"),
            "user": g.username,
            **update_fields,
        }
        _save_manual_scan(entry)
        if not MONGO_READY: _increment_fallback_stats(risk)

    # ── Auto-generate incident report for medium/high risk ────────────────
    if risk in ("medium", "high"):
        user_doc = _get_user(g.username) or {}
        full_scan = {
            "_id":              scan_id,
            "sender":           base.get("_sender", base.get("sender", "")),
            "subject":          base.get("_subject", base.get("subject", "")),
            "body":             base.get("_body", ""),
            "links":            base.get("_links", ""),
            "risk":             risk,
            "risk_score":       final_score,
            "threats":          merged_threats,
            "explanations":     merged_explanations,
            "link_results":     base.get("link_results", []),
            "domain_results":   base.get("domain_results", []),
            "ml_prob":          base.get("ml_prob"),
            "mode":             base.get("mode", "rules only") + " + interview",
            "source":           "manual+interview",
            "interview_answers":answers,
            "score_breakdown":  score_breakdown,
            "time":             datetime.now().strftime("%H:%M:%S"),
            "date":             datetime.now().strftime("%d %b %Y"),
        }
        send_incident_report(
            scan             = full_scan,
            reporter         = g.username,
            gmail_address    = user_doc.get("gmail", ""),
            app_password     = user_doc.get("app_password", ""),
            it_email         = IT_EMAIL,
            scans_col        = _scans_col,
            manual_scans_col = _manual_scans_col,
        )

    result = dict(base)
    result.update({
        "risk": risk, "risk_score": final_score,
        "threats": merged_threats, "explanations": merged_explanations,
        "link_results": base.get("link_results", []),
        "interview_score": interview_contribution,
        "base_score": base_score,
        "score_breakdown": score_breakdown,
        "scan_id": scan_id,
    })
    return jsonify(result)


@app.route("/api/history", methods=["GET"])
@require_auth
def api_history():
    limit = min(int(request.args.get("limit", 100)), 200)
    docs  = _get_manual_history(g.username, limit)
    return jsonify({"history": docs, "count": len(docs)})


@app.route("/api/dashboard", methods=["GET"])
@require_auth
def api_dashboard():
    return jsonify({
        "stats":       _get_stats(),
        "scans":       _get_scans(200),
        "mongo_ready": MONGO_READY,
    })


@app.route("/api/scans/<scan_id>", methods=["GET"])
@require_auth
def get_scan(scan_id):
    if not MONGO_READY:
        return jsonify({"error": "MongoDB not available"}), 503
    try:
        doc = _scans_col.find_one({"_id": ObjectId(scan_id)})
        if not doc: return jsonify({"error": "Scan not found"}), 404
        doc["_id"] = str(doc["_id"])
        if "created_at" in doc: doc["created_at"] = doc["created_at"].isoformat()
        return jsonify(doc)
    except InvalidId:
        return jsonify({"error": "Invalid scan ID"}), 400


@app.route("/config/it-email", methods=["GET", "POST"])
@require_auth
def it_email_config():
    global IT_EMAIL
    if request.method == "POST":
        data  = request.get_json() or {}
        email = (data.get("it_email") or "").strip()
        if not email or "@" not in email:
            return jsonify({"error": "Invalid email address"}), 400
        IT_EMAIL = email
        print(f"  [Config] IT_EMAIL set to {IT_EMAIL}", flush=True)
        return jsonify({"message": "IT email updated", "it_email": IT_EMAIL})
    return jsonify({"it_email": IT_EMAIL})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok", "ml_ready": ML_READY,
        "mode": "ML + rules" if ML_READY else "rules only",
        "mongo_ready": MONGO_READY,
        "mongo_uri": MONGO_URI if MONGO_READY else None,
    })


@app.route("/health/db", methods=["GET"])
def health_db():
    if not MONGO_READY:
        return jsonify({"mongo_ready": False, "error": "MongoDB not connected"}), 503
    try:
        r = _scans_col.insert_one({"_test": True, "ts": datetime.utcnow()})
        _scans_col.delete_one({"_id": r.inserted_id})
        return jsonify({
            "mongo_ready":    True,
            "write_test":     "PASSED",
            "total_scans":    _scans_col.count_documents({}),
            "manual_scans":   _manual_scans_col.count_documents({}),
            "interview_scans":_manual_scans_col.count_documents({"source": "manual+interview"}),
            "monitor_scans":  _scans_col.count_documents({"source": "monitor"}),
        })
    except Exception as e:
        return jsonify({"mongo_ready": True, "write_test": "FAILED", "error": str(e)}), 500


if __name__ == "__main__":
    print("\n  PhishGuard v5  running:")
    print("  Login     -> http://localhost:5000")
    print("  App       -> http://localhost:5000/app")
    print("  Dashboard -> http://localhost:5000/dashboard")
    print(f"  ML mode   -> {'enabled' if ML_READY else 'disabled'}")
    print(f"  MongoDB   -> {'connected' if MONGO_READY else 'fallback (in-memory)'}\n")
    app.run(debug=True, port=5000)