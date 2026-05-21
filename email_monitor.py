"""
PhishGuard - Gmail Monitor
Polls Gmail via IMAP every 30 seconds, sends unseen emails to
your Flask /analyze endpoint, and fires a Windows desktop notification
only for MEDIUM and HIGH risk emails.
"""

import imaplib
import email
from email.header import decode_header
import requests
import time
import re
from plyer import notification

# ── CONFIG ─────────────────────────────────────────────────────────────
GMAIL_ADDRESS      = "pchinte123@gmail.com"
GMAIL_APP_PASSWORD = "gkdahpeetearwhlx"   # 16 chars, no spaces
FLASK_URL          = "http://localhost:5000/analyze"
POLL_INTERVAL      = 30   # seconds
NOTIFY_ON          = ["medium", "high"]  # only alert these risk levels
# ──────────────────────────────────────────────────────────────────────


def decode_str(value):
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


def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition", ""))
            if ctype == "text/plain" and "attachment" not in disp:
                charset = part.get_content_charset() or "utf-8"
                try:
                    body += part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    pass
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            body = msg.get_payload(decode=True).decode(charset, errors="replace")
        except Exception:
            body = ""
    return body


def extract_links(body):
    urls = re.findall(r'https?://[^\s<>"\']+', body)
    return "\n".join(urls)


def analyze(sender, subject, body, links):
    try:
        resp = requests.post(FLASK_URL, json={
            "sender":  sender,
            "subject": subject,
            "body":    body,
            "links":   links,
            "headers": "",
            "source":  "monitor"
        }, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print("  [!] Flask error: {}".format(e))
        return None


def safe_truncate(text, max_len):
    """Truncate string to max_len, safely."""
    text = str(text)
    return text[:max_len - 3] + "..." if len(text) > max_len else text


def notify_user(sender, subject, risk, risk_score, threats):
    """Fire a Windows desktop notification — strictly within Windows char limits."""
    icons = {"high": "[HIGH RISK]", "medium": "[MEDIUM RISK]", "low": "[LOW RISK]"}
    icon  = icons.get(risk, "[?]")

    # Windows title max = 63 chars, message max = 255 chars
    title   = safe_truncate("{} {}".format(icon, subject), 63)
    threat_labels = ", ".join(t["label"] for t in threats[:2])
    message = safe_truncate(
        "Score: {}/100 | {}\nFrom: {}".format(risk_score, threat_labels, sender),
        255
    )

    try:
        notification.notify(
            title=title,
            message=message,
            app_name="PhishGuard",
            timeout=10
        )
    except Exception as e:
        print("  [!] Notification error: {}".format(e))


def check_inbox(mail, seen_ids):
    try:
        mail.select("inbox")
        _, data = mail.search(None, "UNSEEN")
        email_ids = data[0].split()
        new_ids = [eid for eid in email_ids if eid not in seen_ids]

        for eid in new_ids:
            seen_ids.add(eid)
            _, msg_data = mail.fetch(eid, "(RFC822)")
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)

            sender  = decode_str(msg.get("From", ""))
            subject = decode_str(msg.get("Subject", "(no subject)"))
            body    = extract_body(msg)
            links   = extract_links(body)

            print("\n  From:    {}".format(sender[:60]))
            print("  Subject: {}".format(subject[:60]))
            print("  Analyzing...")

            result = analyze(sender, subject, body, links)
            if not result:
                continue

            risk       = result.get("risk", "unknown")
            risk_score = result.get("risk_score", 0)
            threats    = result.get("threats", [])

            print("  Result:  {} ({}/100)".format(risk.upper(), risk_score))

            # Only notify for medium and high risk
            if risk in NOTIFY_ON:
                notify_user(sender, subject, risk, risk_score, threats)
                print("  [!] Notification sent!")

        return seen_ids

    except imaplib.IMAP4.error as e:
        print("  [!] IMAP error: {}".format(e))
        return seen_ids


def main():
    print("\n  PhishGuard Gmail Monitor starting...")
    print("  Polling every {}s | Flask at {}".format(POLL_INTERVAL, FLASK_URL))
    print("  Notifying on: {}\n".format(", ".join(NOTIFY_ON)))

    seen_ids = set()

    while True:
        try:
            print("  Connecting to Gmail IMAP...")
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            print("  Connected. Watching inbox...\n")

            while True:
                seen_ids = check_inbox(mail, seen_ids)
                time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print("\n  Stopped.")
            break
        except Exception as e:
            print("  [!] Connection lost: {}. Reconnecting in 15s...".format(e))
            time.sleep(15)


if __name__ == "__main__":
    main()