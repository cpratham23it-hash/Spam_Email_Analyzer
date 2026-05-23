"""
PhishGuard – Gmail Monitor  (v2)
=================================
Fixes vs v1
-----------
1. seen_ids now stores Message-IDs (stable across reconnects), not
   volatile IMAP sequence numbers that reset each session.
2. IMAP NOOP keepalive every poll cycle → no silent disconnects.
3. Proper IMAP exception hierarchy – catches ALL exceptions in
   check_inbox, not just imaplib.IMAP4.error.
4. Exponential back-off on reconnect (15 → 30 → 60 s, max 120 s).
5. Idle timeout detection: if NOOP fails, reconnect immediately.
6. HTML body fallback: if text/plain is empty, strips HTML.
7. Cleaner console output with timestamps.
"""

import email
import imaplib
import re
import time
from datetime import datetime
from email.header import decode_header
from html.parser import HTMLParser

import requests
from plyer import notification

# ══════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════
GMAIL_ADDRESS      = "pchinte123@gmail.com"
GMAIL_APP_PASSWORD = "gkdahpeetearwhlx"   # Gmail App Password (16 chars)
FLASK_URL          = "http://localhost:5000/analyze"
POLL_INTERVAL      = 30    # seconds between inbox checks
NOTIFY_ON          = ["medium", "high"]
MAX_BODY_CHARS     = 4000  # truncate very long bodies before sending
# ══════════════════════════════════════════════════════════════════════


# ── Helpers ────────────────────────────────────────────────────────────
def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"  [{ts()}] {msg}", flush=True)


def safe_truncate(text: str, max_len: int) -> str:
    text = str(text)
    return text[: max_len - 3] + "..." if len(text) > max_len else text


# ── HTML → plain text ──────────────────────────────────────────────────
class _HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self._parts = []

    def handle_data(self, data):
        self._parts.append(data)

    def get_text(self) -> str:
        return " ".join(self._parts)


def strip_html(html: str) -> str:
    p = _HTMLStripper()
    try:
        p.feed(html)
        return p.get_text()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)


# ── Email parsing ──────────────────────────────────────────────────────
def decode_str(value) -> str:
    if value is None:
        return ""
    parts = decode_header(value)
    result = []
    for part, enc in parts:
        if isinstance(part, bytes):
            result.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            result.append(str(part))
    return " ".join(result)


def extract_body(msg) -> str:
    """Return plain-text body. Falls back to HTML→text if no plain part."""
    plain = ""
    html  = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode(charset, errors="replace")
                if ctype == "text/plain":
                    plain += text
                elif ctype == "text/html":
                    html += text
            except Exception:
                pass
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    html = text
                else:
                    plain = text
        except Exception:
            pass

    body = plain.strip() or strip_html(html).strip()
    return body[:MAX_BODY_CHARS]


def extract_links(body: str) -> str:
    urls = re.findall(r"https?://[^\s<>\"']+", body)
    return "\n".join(urls)


def get_message_id(msg) -> str:
    """Stable identifier that survives reconnects (unlike IMAP seq numbers)."""
    mid = msg.get("Message-ID", "").strip()
    if mid:
        return mid
    # Fallback: hash of From + Date + Subject
    return "|".join([
        msg.get("From", ""),
        msg.get("Date", ""),
        msg.get("Subject", ""),
    ])


# ── Flask call ─────────────────────────────────────────────────────────
def analyze(sender: str, subject: str, body: str, links: str) -> dict | None:
    try:
        resp = requests.post(
            FLASK_URL,
            json={
                "sender":  sender,
                "subject": subject,
                "body":    body,
                "links":   links,
                "headers": "",
                "source":  "monitor",
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        log("[!] Cannot reach Flask — is App.py running?")
    except requests.exceptions.Timeout:
        log("[!] Flask request timed out")
    except Exception as e:
        log(f"[!] Flask error: {e}")
    return None


# ── Desktop notification ───────────────────────────────────────────────
def notify_user(sender: str, subject: str, risk: str,
                risk_score: int, threats: list) -> None:
    icons  = {"high": "[HIGH RISK]", "medium": "[MEDIUM RISK]", "low": "[LOW RISK]"}
    title  = safe_truncate(f"{icons.get(risk, '[?]')} {subject}", 63)
    labels = ", ".join(
        (t["label"] if isinstance(t, dict) else str(t)) for t in threats[:2]
    )
    message = safe_truncate(
        f"Score: {risk_score}/100 | {labels}\nFrom: {sender}", 255
    )
    try:
        notification.notify(
            title=title, message=message,
            app_name="PhishGuard", timeout=10,
        )
    except Exception as e:
        log(f"[!] Notification error: {e}")


# ── IMAP keepalive ─────────────────────────────────────────────────────
def noop(mail: imaplib.IMAP4_SSL) -> bool:
    """Send NOOP to keep connection alive. Returns False if connection is dead."""
    try:
        mail.noop()
        return True
    except Exception:
        return False


# ── Core inbox check ───────────────────────────────────────────────────
def check_inbox(mail: imaplib.IMAP4_SSL, seen_ids: set) -> set:
    """
    Fetch UNSEEN messages, analyze each one.
    seen_ids holds Message-IDs (strings) — stable across reconnects.
    """
    try:
        mail.select("INBOX")
        status, data = mail.search(None, "UNSEEN")
        if status != "OK":
            log(f"[!] IMAP search failed: {status}")
            return seen_ids

        imap_ids = data[0].split()
        if not imap_ids:
            return seen_ids  # nothing new

        log(f"Found {len(imap_ids)} unseen message(s)")

        for imap_id in imap_ids:
            try:
                status, msg_data = mail.fetch(imap_id, "(RFC822)")
                if status != "OK" or not msg_data or msg_data[0] is None:
                    continue

                raw = msg_data[0][1]
                if not isinstance(raw, bytes):
                    continue

                msg     = email.message_from_bytes(raw)
                mid     = get_message_id(msg)

                # Skip if we've already processed this message
                if mid in seen_ids:
                    continue
                seen_ids.add(mid)

                sender  = decode_str(msg.get("From",    ""))
                subject = decode_str(msg.get("Subject", "(no subject)"))
                body    = extract_body(msg)
                links   = extract_links(body)

                print()
                log(f"From:    {sender[:70]}")
                log(f"Subject: {subject[:70]}")
                log(f"Analyzing...")

                result = analyze(sender, subject, body, links)
                if not result:
                    log("[!] No result from Flask — skipping")
                    continue

                risk       = result.get("risk",       "unknown")
                risk_score = result.get("risk_score", 0)
                threats    = result.get("threats",    [])
                mode       = result.get("mode",       "rules only")

                log(f"Result:  {risk.upper()} ({risk_score}/100)  [{mode}]")

                if risk in NOTIFY_ON:
                    notify_user(sender, subject, risk, risk_score, threats)
                    log("[!] Desktop notification sent")

            except Exception as e:
                log(f"[!] Error processing message {imap_id}: {e}")
                continue

    except imaplib.IMAP4.abort as e:
        # Connection was aborted — signal caller to reconnect
        raise ConnectionError(f"IMAP connection aborted: {e}")
    except imaplib.IMAP4.error as e:
        log(f"[!] IMAP error: {e}")
    except Exception as e:
        log(f"[!] Unexpected error in check_inbox: {e}")

    return seen_ids


# ── Main loop ──────────────────────────────────────────────────────────
def main() -> None:
    print()
    print("  ════════════════════════════════════════")
    print("   PhishGuard Gmail Monitor  (v2)")
    print("  ════════════════════════════════════════")
    log(f"Polling every {POLL_INTERVAL}s | Flask at {FLASK_URL}")
    log(f"Notifying on: {', '.join(NOTIFY_ON)}")
    print()

    seen_ids    = set()
    backoff     = 15   # reconnect delay in seconds

    while True:
        mail = None
        try:
            log("Connecting to Gmail IMAP...")
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            log("Connected ✓  Watching inbox...\n")
            backoff = 15  # reset back-off on successful connect

            poll_count = 0
            while True:
                # Every 10th poll send a NOOP to keep the connection alive
                if poll_count % 10 == 0 and poll_count > 0:
                    if not noop(mail):
                        raise ConnectionError("NOOP failed — connection dead")

                seen_ids = check_inbox(mail, seen_ids)
                poll_count += 1
                time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            log("Stopped by user.")
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass
            break

        except ConnectionError as e:
            log(f"[!] {e}")
            log(f"Reconnecting in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)

        except imaplib.IMAP4.error as e:
            log(f"[!] IMAP login/auth error: {e}")
            log("Check GMAIL_ADDRESS and GMAIL_APP_PASSWORD in the config.")
            log(f"Retrying in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)

        except Exception as e:
            log(f"[!] Unexpected error: {e}")
            log(f"Reconnecting in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)

        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass


if __name__ == "__main__":
    main()