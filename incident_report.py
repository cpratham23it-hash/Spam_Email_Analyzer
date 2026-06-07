"""
PhishGuard – Incident Report Module
Generates HTML reports and emails them to the IT team.
"""
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from datetime             import datetime

try:
    from pymongo import MongoClient
    from bson    import ObjectId
except ImportError:
    ObjectId = str


def build_report_html(scan: dict, reporter: str) -> str:
    risk        = scan.get("risk", "unknown").upper()
    risk_score  = scan.get("risk_score", 0)
    sender_val  = scan.get("sender", "—")
    subject_val = scan.get("subject", "—")
    body_val    = (scan.get("body", "") or "")[:500]
    links_val   = (scan.get("links", "") or "").replace("\n", "<br>") or "None"
    mode_val    = scan.get("mode", "—")
    source_val  = scan.get("source", "—")
    date_val    = f"{scan.get('date','')} {scan.get('time','')}".strip()
    ml_prob     = scan.get("ml_prob")
    threats     = scan.get("threats", [])
    explanations= scan.get("explanations", [])
    interview   = scan.get("interview_answers", {})
    breakdown   = scan.get("score_breakdown") or {}
    domain_res  = scan.get("domain_results", [])

    risk_color = {"HIGH": "#ff4d6a", "MEDIUM": "#ffb547", "LOW": "#00d4aa"}.get(risk, "#888")

    def threat_type_to_color(t):
        return "#ff4d6a" if t == "danger" else "#ffb547" if t == "warn" else "#8899ff"

    def threat_type_to_icon(t):
        return "&#x26D4;" if t == "danger" else "&#x26A0;" if t == "warn" else "&#x2139;"

    threat_rows = "".join(
        "<tr><td style='padding:6px 10px;border-bottom:1px solid #222;'>"
        "<span style='color:{c};'>{i} {l}</span></td></tr>".format(
            c=threat_type_to_color(t.get("type", "info")),
            i=threat_type_to_icon(t.get("type", "info")),
            l=t.get("label", "")
        ) for t in threats
    )

    expl_rows = "".join(
        "<tr><td style='padding:5px 10px;border-bottom:1px solid #1a1a1a;"
        "color:#aaa;font-size:13px;'>&#x2022; {e}</td></tr>".format(e=e)
        for e in explanations
    )

    q_labels = {
        "q1": "Were you expecting this email?",
        "q2": "Do you recognise the sender?",
        "q3": "Action requested?",
        "q4": "Urgency / fear tactics?",
        "q5": "Part of a recent pattern?",
    }
    interview_rows = "".join(
        "<tr>"
        "<td style='padding:5px 10px;color:#aaa;border-bottom:1px solid #1a1a1a;"
        "width:55%;font-size:12px;'>{q}</td>"
        "<td style='padding:5px 10px;color:#e8eaf2;border-bottom:1px solid #1a1a1a;"
        "font-size:12px;'>{v}</td>"
        "</tr>".format(q=q_labels.get(k, k), v=v)
        for k, v in interview.items()
    ) if interview else "<tr><td colspan='2' style='color:#666;padding:8px;font-size:12px;'>No interview data</td></tr>"

    domain_rows = "".join(
        "<tr>"
        "<td style='padding:5px 10px;border-bottom:1px solid #1a1a1a;color:#aaa;font-size:12px;'>"
        "{badge} {domain}</td>"
        "<td style='padding:5px 10px;border-bottom:1px solid #1a1a1a;font-size:12px;"
        "color:{ic};'>{ip}</td>"
        "<td style='padding:5px 10px;border-bottom:1px solid #1a1a1a;color:#aaa;font-size:12px;'>"
        "{age}</td></tr>".format(
            badge="&#x2709;" if d.get("kind") == "sender" else "&#x1F517;",
            domain=d.get("domain", ""),
            ic="#ff4d6a" if not d.get("exists") else "#00d4aa",
            ip="No DNS record" if not d.get("exists") else (d.get("ip") or "resolved"),
            age=str(d.get("age_days")) + "d old" if d.get("age_days") is not None else "age unknown"
        )
        for d in domain_res
    ) if domain_res else "<tr><td colspan='3' style='color:#666;padding:8px;font-size:12px;'>No domain validation data</td></tr>"

    if breakdown:
        breakdown_rows = (
            "<tr><td style='padding:5px 10px;color:#aaa;border-bottom:1px solid #1a1a1a;font-size:12px;'>ML / Rules score</td>"
            "<td style='padding:5px 10px;color:#e8eaf2;border-bottom:1px solid #1a1a1a;font-size:12px;'>{v} / 100</td></tr>"
            "<tr><td style='padding:5px 10px;color:#aaa;border-bottom:1px solid #1a1a1a;font-size:12px;'>Interview adjustment</td>"
            "<td style='padding:5px 10px;color:#e8eaf2;border-bottom:1px solid #1a1a1a;font-size:12px;'>+{i}</td></tr>"
            "<tr><td style='padding:5px 10px;color:#aaa;border-bottom:1px solid #1a1a1a;font-size:12px;'>Weighting</td>"
            "<td style='padding:5px 10px;color:#e8eaf2;border-bottom:1px solid #1a1a1a;font-size:12px;'>{w}</td></tr>"
            "<tr><td style='padding:5px 10px;color:#00d4aa;font-weight:600;font-size:12px;'>Final score</td>"
            "<td style='padding:5px 10px;color:#00d4aa;font-weight:600;font-size:12px;'>{f} / 100</td></tr>"
        ).format(
            v=breakdown.get("ml_rules_score", "?"),
            i=breakdown.get("interview_delta", "?"),
            w=breakdown.get("weights", "?"),
            f=breakdown.get("final_score", "?"),
        )
    else:
        breakdown_rows = "<tr><td colspan='2' style='color:#666;padding:8px;font-size:12px;'>No breakdown data</td></tr>"

    ml_row = ""
    if ml_prob:
        ml_row = ("<tr><td style='padding:8px 14px;color:#6b7590;font-size:12px;'>"
                  "ML probability</td><td style='padding:8px 14px;font-size:13px;'>"
                  "{p}% phishing</td></tr>").format(p=ml_prob)

    html = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>PhishGuard Incident Report</title></head>
<body style="margin:0;padding:0;background:#0a0d12;font-family:'Segoe UI',Arial,sans-serif;color:#e8eaf2;">
<div style="max-width:700px;margin:30px auto;background:#111520;border:1px solid #1d2438;border-radius:16px;overflow:hidden;">

  <div style="background:linear-gradient(135deg,#0a0d12,#161c2a);padding:28px 32px;border-bottom:1px solid #1d2438;">
    <table style="width:100%;border-collapse:collapse;"><tr>
      <td style="vertical-align:middle;">
        <div style="display:inline-block;width:44px;height:44px;border-radius:10px;background:linear-gradient(135deg,#00d4aa,#0096ff);text-align:center;line-height:44px;font-size:22px;vertical-align:middle;margin-right:14px;">&#x1F6E1;</div>
        <span style="font-size:20px;font-weight:700;vertical-align:middle;">PhishGuard</span><br>
        <span style="font-size:12px;color:#6b7590;margin-left:58px;">Automated Incident Report</span>
      </td>
      <td style="text-align:right;vertical-align:top;">
        <div style="display:inline-block;background:{rc}22;color:{rc};border:1px solid {rc}44;padding:6px 16px;border-radius:20px;font-size:13px;font-weight:700;">{risk} RISK</div>
        <div style="font-size:11px;color:#6b7590;margin-top:4px;">Score: {rs} / 100</div>
      </td>
    </tr></table>
  </div>

  <div style="padding:28px 32px;">

    <div style="font-size:11px;font-family:monospace;color:#6b7590;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Report Details</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;background:#161c2a;border-radius:10px;overflow:hidden;">
      <tr><td style="padding:8px 14px;color:#6b7590;font-size:12px;width:140px;border-bottom:1px solid #1d2438;">Reported by</td><td style="padding:8px 14px;font-size:13px;border-bottom:1px solid #1d2438;">{reporter}</td></tr>
      <tr><td style="padding:8px 14px;color:#6b7590;font-size:12px;border-bottom:1px solid #1d2438;">Date / Time</td><td style="padding:8px 14px;font-size:13px;border-bottom:1px solid #1d2438;">{date}</td></tr>
      <tr><td style="padding:8px 14px;color:#6b7590;font-size:12px;border-bottom:1px solid #1d2438;">Detection mode</td><td style="padding:8px 14px;font-size:13px;font-family:monospace;border-bottom:1px solid #1d2438;">{mode}</td></tr>
      <tr><td style="padding:8px 14px;color:#6b7590;font-size:12px;border-bottom:1px solid #1d2438;">Source</td><td style="padding:8px 14px;font-size:13px;font-family:monospace;border-bottom:1px solid #1d2438;">{source}</td></tr>
      {ml_row}
    </table>

    <div style="font-size:11px;font-family:monospace;color:#6b7590;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Suspicious Email</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;background:#161c2a;border-radius:10px;overflow:hidden;">
      <tr><td style="padding:8px 14px;color:#6b7590;font-size:12px;width:80px;border-bottom:1px solid #1d2438;">From</td><td style="padding:8px 14px;font-size:13px;font-family:monospace;color:#ff4d6a;border-bottom:1px solid #1d2438;">{sender}</td></tr>
      <tr><td style="padding:8px 14px;color:#6b7590;font-size:12px;border-bottom:1px solid #1d2438;">Subject</td><td style="padding:8px 14px;font-size:13px;border-bottom:1px solid #1d2438;">{subject}</td></tr>
      <tr><td style="padding:8px 14px;color:#6b7590;font-size:12px;border-bottom:1px solid #1d2438;">Links</td><td style="padding:8px 14px;font-size:12px;font-family:monospace;color:#ffb547;border-bottom:1px solid #1d2438;">{links}</td></tr>
      <tr><td style="padding:8px 14px;color:#6b7590;font-size:12px;vertical-align:top;">Body</td><td style="padding:8px 14px;font-size:12px;color:#aaa;">{body}</td></tr>
    </table>

    <div style="font-size:11px;font-family:monospace;color:#6b7590;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Detected Threats</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;background:#161c2a;border-radius:10px;overflow:hidden;">{threat_rows}</table>

    <div style="font-size:11px;font-family:monospace;color:#6b7590;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Domain Validation</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;background:#161c2a;border-radius:10px;overflow:hidden;">
      <tr style="background:#1d2438;"><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7590;">Domain</th><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7590;">IP / Status</th><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7590;">Age</th></tr>
      {domain_rows}
    </table>

    <div style="font-size:11px;font-family:monospace;color:#6b7590;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Explanation</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;background:#161c2a;border-radius:10px;overflow:hidden;">{expl_rows}</table>

    <div style="font-size:11px;font-family:monospace;color:#6b7590;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">User Interview Answers</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;background:#161c2a;border-radius:10px;overflow:hidden;">{interview_rows}</table>

    <div style="font-size:11px;font-family:monospace;color:#6b7590;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Score Breakdown</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:8px;background:#161c2a;border-radius:10px;overflow:hidden;">{breakdown_rows}</table>

  </div>

  <div style="padding:16px 32px;border-top:1px solid #1d2438;text-align:center;font-size:11px;color:#6b7590;">
    This report was automatically generated by PhishGuard AI Phishing Detection System.<br>
    Please do not reply to this email. Forward suspicious activity to your IT security team.
  </div>
</div>
</body>
</html>""".format(
        rc=risk_color, risk=risk, rs=risk_score,
        reporter=reporter, date=date_val, mode=mode_val,
        source=source_val, ml_row=ml_row,
        sender=sender_val, subject=subject_val,
        links=links_val, body=body_val,
        threat_rows=threat_rows, domain_rows=domain_rows,
        expl_rows=expl_rows, interview_rows=interview_rows,
        breakdown_rows=breakdown_rows,
    )
    return html


def send_incident_report(scan: dict, reporter: str, gmail_address: str,
                          app_password: str, it_email: str,
                          scans_col=None, manual_scans_col=None):
    """
    Send HTML incident report to IT email in a background thread.
    """
    if not it_email or not gmail_address or not app_password:
        print("  [Report] Skipping — IT_EMAIL or Gmail credentials not configured", flush=True)
        return

    def _send():
        try:
            risk    = scan.get("risk", "unknown").upper()
            subject = scan.get("subject", "(no subject)")

            msg = MIMEMultipart("alternative")
            msg["Subject"] = "[PhishGuard] {r} RISK Incident — {s}".format(
                r=risk, s=subject[:60])
            msg["From"] = "PhishGuard <{g}>".format(g=gmail_address)
            msg["To"]   = it_email

            html_body = build_report_html(scan, reporter)
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
                server.login(gmail_address, app_password)
                server.sendmail(gmail_address, it_email, msg.as_string())

            # Update scan doc with report status
            report_meta = {
                "incident_report_sent":    True,
                "incident_report_sent_at": datetime.utcnow().isoformat(),
                "incident_report_to":      it_email,
            }
            scan_id = scan.get("_id", "")
            source  = scan.get("source", "")
            if scan_id:
                try:
                    col = manual_scans_col if "manual" in source else scans_col
                    if col:
                        col.update_one({"_id": ObjectId(scan_id)},
                                       {"$set": report_meta})
                except Exception:
                    pass

            print("  [Report] Sent to {e}  risk={r}".format(
                e=it_email, r=risk), flush=True)

        except Exception as e:
            print("  [Report] FAILED: {e}".format(e=e), flush=True)

    threading.Thread(target=_send, daemon=True, name="incident-report").start()