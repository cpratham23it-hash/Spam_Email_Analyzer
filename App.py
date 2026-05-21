from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import re
from datetime import datetime
from collections import deque

app = Flask(__name__, static_folder=".")
CORS(app)

# ── In-memory scan log (last 200 scans) ───────────────────────────────
scan_log = deque(maxlen=200)
stats = {"total": 0, "high": 0, "medium": 0, "low": 0}


def analyze_email(sender, subject, body, links, headers):
    score = 0
    threats = []
    link_results = []
    explanations = []

    sender_lower = sender.lower()

    if re.search(r'paypa[l1]|amaz[o0]n|g[o0]{2}gle|micr[o0]s[o0]ft|app[l1]e|netf[l1]ix|faceb[o0]{2}k', sender_lower):
        score += 35
        threats.append({"label": "Spoofed sender domain", "type": "danger"})
        explanations.append("The sender mimics a well-known brand using character substitution.")

    if re.search(r'\.(xyz|tk|ml|ga|cf|top|loan|work|click|gq)$', sender_lower):
        score += 20
        threats.append({"label": "Suspicious TLD", "type": "danger"})
        explanations.append("The sender domain uses a TLD commonly associated with phishing.")

    if "reply-to" in headers.lower():
        sender_domain = sender.split("@")[-1] if "@" in sender else ""
        if sender_domain and sender_domain not in headers.lower():
            score += 15
            threats.append({"label": "Reply-To mismatch", "type": "warn"})
            explanations.append("The Reply-To header points to a different domain than the sender.")

    subj_lower = subject.lower()
    urgency_words = ["urgent", "immediate", "suspended", "verify", "confirm",
                     "unusual activity", "account locked", "expires", "action required",
                     "final notice", "warning"]
    hits = [w for w in urgency_words if w in subj_lower]
    if hits:
        score += min(15 * len(hits), 30)
        threats.append({"label": "Urgency language in subject", "type": "warn"})
        explanations.append("Subject contains urgency trigger words: {}.".format(", ".join(hits[:3])))

    if len(subject) > 5 and sum(1 for c in subject if c.isupper()) > len(subject) * 0.5:
        score += 8
        threats.append({"label": "Excessive caps in subject", "type": "info"})

    body_lower = body.lower()
    phish_keywords = ["click here", "verify your account", "sign in", "update your information",
                      "your account has been", "limited time", "winner", "prize",
                      "congratulations", "free gift", "bank details", "password",
                      "credit card", "ssn", "social security"]
    body_hits = [w for w in phish_keywords if w in body_lower]
    if len(body_hits) >= 2:
        score += min(10 * len(body_hits), 30)
        threats.append({"label": "Phishing keywords detected", "type": "warn"})
        joined = '", "'.join(body_hits[:3])
        explanations.append("Body contains {} known phishing phrases: \"{}\".".format(len(body_hits), joined))

    if re.search(r'<a\s+href', body, re.IGNORECASE):
        score += 10
        threats.append({"label": "HTML anchor tags in body", "type": "info"})

    link_list = [l.strip() for l in links.split("\n") if l.strip()]
    suspicious_found = False

    for url in link_list:
        u = url.lower()
        status = "safe"
        reason = "OK"

        if re.search(r'bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|rebrand\.ly', u):
            status, reason = "warn", "URL shortener"
            score += 12

        if re.search(r'paypa[l1]|amaz[o0]n|g[o0]{2}gle|micr[o0]s[o0]ft', u):
            domain = u.split("/")[2] if len(u.split("/")) > 2 else u
            if not re.search(r'\.(com|co\.uk|org)$', domain):
                status, reason = "danger", "Brand impersonation"
                score += 25

        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u):
            status, reason = "danger", "IP address URL"
            score += 20

        if status == "safe" and re.search(r'login|signin|verify|account|update|secure|banking', u):
            status, reason = "warn", "Credential-harvesting path"
            score += 10

        domain_part = u.split("/")[2] if len(u.split("/")) > 2 else u
        if re.search(r'\.(xyz|tk|ml|top|loan)$', domain_part):
            status, reason = "danger", "Suspicious TLD"
            score += 15

        link_results.append({"url": url, "status": status, "reason": reason})
        if status != "safe" and not suspicious_found:
            suspicious_found = True
            threats.append({"label": "Suspicious links detected", "type": "danger"})
            explanations.append("One or more links show signs of URL obfuscation or brand impersonation.")

    score = min(score, 100)
    if score < 30:
        risk, risk_score = "low", max(score, 5)
    elif score < 65:
        risk, risk_score = "medium", score
    else:
        risk, risk_score = "high", min(score, 98)

    if not threats:
        threats.append({"label": "No threats detected", "type": "info"})
        explanations.append("No obvious phishing indicators found. Stay cautious with unexpected emails.")

    return {"risk": risk, "risk_score": risk_score, "threats": threats,
            "link_results": link_results, "explanations": explanations}


# ── Routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/dashboard")
def dashboard():
    return send_from_directory(".", "dashboard.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body received"}), 400

    sender  = data.get("sender", "")
    subject = data.get("subject", "")
    body    = data.get("body", "")
    links   = data.get("links", "")
    headers = data.get("headers", "")
    source  = data.get("source", "manual")   # "manual" or "monitor"

    if not sender and not subject and not body:
        return jsonify({"error": "Provide at least sender, subject, or body"}), 400

    result = analyze_email(sender, subject, body, links, headers)

    # Log to dashboard
    entry = {
        "id":        stats["total"] + 1,
        "time":      datetime.now().strftime("%H:%M:%S"),
        "date":      datetime.now().strftime("%d %b %Y"),
        "sender":    sender[:80],
        "subject":   subject[:100],
        "risk":      result["risk"],
        "risk_score": result["risk_score"],
        "threats":   [t["label"] for t in result["threats"]],
        "source":    source
    }
    scan_log.appendleft(entry)
    stats["total"] += 1
    stats[result["risk"]] += 1

    return jsonify(result)


@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    """Returns live stats + recent scan log for the dashboard."""
    return jsonify({
        "stats": dict(stats),
        "scans": list(scan_log)
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "PhishGuard API running"})


if __name__ == "__main__":
    print("\n  PhishGuard running:")
    print("  App       -> http://localhost:5000")
    print("  Dashboard -> http://localhost:5000/dashboard\n")
    app.run(debug=True, port=5000)