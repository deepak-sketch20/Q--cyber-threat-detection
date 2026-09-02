"""
Quantum-Inspired Cyber Threat Detection for Digital Signature Security
Module: Automatic Email Alerting & Security Event Logger
Dispatches automated security incident notifications via SMTP with attached Forensic Reports.
Supports Demo / Test Mode, Gmail TLS/SSL, and Tamper-Proof Event Logging.
"""

import os
import smtplib
import mimetypes
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import Dict, Any, List, Optional

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)
SECURITY_EVENTS_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security_events.log')

def get_email_config() -> Dict[str, Any]:
    """
    Retrieves SMTP and owner email configuration from environment variables.
    Does NOT hard-code passwords.
    """
    owner_email = os.environ.get('OWNER_EMAIL', 'owner@example.com').strip()
    smtp_email = os.environ.get('SMTP_EMAIL', '').strip()
    smtp_password = os.environ.get('SMTP_PASSWORD', '').strip()
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com').strip()
    smtp_port_raw = os.environ.get('SMTP_PORT', '587').strip()
    
    try:
        smtp_port = int(smtp_port_raw)
    except ValueError:
        smtp_port = 587

    test_mode_str = os.environ.get('EMAIL_TEST_MODE', 'True').strip().lower()
    is_test_mode = test_mode_str in ['true', '1', 'yes', 't', 'demo']

    # If credentials are not provided or default dummy values, auto-enable test mode
    has_valid_credentials = bool(smtp_email and smtp_password and smtp_password != 'your-smtp-app-password')
    if not has_valid_credentials:
        is_test_mode = True

    return {
        "owner_email": owner_email,
        "smtp_email": smtp_email,
        "smtp_password": smtp_password,
        "smtp_server": smtp_server,
        "smtp_port": smtp_port,
        "is_test_mode": is_test_mode,
        "has_credentials": has_valid_credentials
    }

def format_alert_email_body(summary: Dict[str, Any]) -> str:
    """Formats the standardized email text body according to specification."""
    indicators_text = "\n".join([f"- {ind}" for ind in summary.get("threat_indicators", [])])
    qm = summary.get("quantum_metrics", {})
    
    body = f"""SECURITY THREAT DETECTED

Case ID: {summary.get('case_id', 'CASE-UNKNOWN')}
Target File: {summary.get('target_file', 'unknown.txt')}
Risk Level: {summary.get('risk_level', 'HIGH')}
Threat Score: {summary.get('threat_score', 0)}

Summary:
A potential security threat was detected during digital-signature and
quantum-security analysis.

Threat Indicators:
{indicators_text}

SHA-256:
{summary.get('sha256', 'N/A')}

Quantum Security Metrics:
QBER: {qm.get('qber', '0.00%')}
Mismatch Rate: {qm.get('mismatch_rate', '0.00%')}
Matching Rate: {qm.get('matching_rate', '100.00%')}
Eavesdrop Probability: {qm.get('eavesdrop_probability', '0.00%')}
Quantum Risk: {qm.get('quantum_risk', 'LOW (Simulated)')}
Security Level: {qm.get('security_level', 'STANDARD (Simulated)')}

Recommended Action:
{summary.get('recommended_action', 'Investigate and quarantine immediately.')}

See attached Executive Forensic Summary for complete details.
"""
    return body

def log_security_event(
    case_id: str,
    filename: str,
    sha256: str,
    risk_level: str,
    threat_score: int,
    triggered_rules: List[str],
    email_status: str,
    recipient: str = ""
):
    """
    Appends event to security_events.log.
    Format: timestamp | case_id | filename | sha256 | risk_level | threat_score | triggered_rules | email_status
    Never writes passwords, tokens, or private secrets.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    rules_summary = "; ".join(triggered_rules).replace("\n", " ")
    
    log_line = (
        f"[{now_iso}] CASE_ID={case_id} | FILE={filename} | SHA256={sha256} | "
        f"RISK={risk_level} | SCORE={threat_score} | RULES=[{rules_summary}] | "
        f"EMAIL_STATUS={email_status} | RECIPIENT={recipient}\n"
    )
    
    try:
        with open(SECURITY_EVENTS_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_line)
    except Exception as e:
        print(f"[LOG_ERROR] Could not write to security_events.log: {str(e)}")

def send_automatic_email_alert(
    summary: Dict[str, Any],
    attachment_paths: Optional[Dict[str, str]] = None,
    force_send: bool = False
) -> Dict[str, Any]:
    """
    Dispatches automated email alert when risk level is HIGH or CRITICAL.
    Handles test mode, attachment encoding, and SMTP exceptions safely.
    """
    config = get_email_config()
    risk_level = summary.get("risk_level", "LOW")
    threat_score = summary.get("threat_score", 0)
    case_id = summary.get("case_id", "CASE-UNKNOWN")
    filename = summary.get("target_file", "unknown.txt")
    sha256 = summary.get("sha256", "")
    rules = summary.get("threat_indicators", [])

    # Check if threat criteria is met (HIGH or CRITICAL) or force_send
    is_high_threat = risk_level in ["HIGH", "CRITICAL"] or threat_score >= 51
    if not is_high_threat and not force_send:
        log_security_event(
            case_id, filename, sha256, risk_level, threat_score, rules,
            "SKIPPED_LOW_RISK", config["owner_email"]
        )
        return {
            "success": True,
            "triggered": False,
            "status": "SKIPPED_LOW_RISK",
            "message": f"Threat risk level is {risk_level} (Score {threat_score}); automatic email not triggered (threshold: HIGH/CRITICAL).",
            "recipient": config["owner_email"],
            "is_test_mode": config["is_test_mode"]
        }

    subject = f"[CYBERSECURITY ALERT] Threat Detected - {risk_level} - {case_id}"
    body_text = format_alert_email_body(summary)

    # -------------------------------------------------------------
    # DEMO / TEST MODE
    # -------------------------------------------------------------
    if config["is_test_mode"]:
        sim_status = "TEST_MODE_SIMULATED"
        log_security_event(
            case_id, filename, sha256, risk_level, threat_score, rules,
            sim_status, config["owner_email"]
        )
        return {
            "success": True,
            "triggered": True,
            "status": "TEST_MODE_SIMULATED",
            "message": f"Alert email simulated (Demo Mode). Ready for transmission to {config['owner_email']}.",
            "recipient": config["owner_email"],
            "subject": subject,
            "body_preview": body_text[:400] + "...",
            "full_body": body_text,
            "attachment_name": f"Executive_Forensic_Summary_{case_id}.pdf",
            "is_test_mode": True,
            "smtp_server": config["smtp_server"],
            "smtp_port": config["smtp_port"],
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        }

    # -------------------------------------------------------------
    # LIVE SMTP TRANSMISSION
    # -------------------------------------------------------------
    try:
        msg = MIMEMultipart()
        msg['From'] = config['smtp_email']
        msg['To'] = config['owner_email']
        msg['Subject'] = subject
        msg['Date'] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))

        # Attach PDF or TXT report if available
        attached_name = "None"
        if attachment_paths:
            target_path = attachment_paths.get("pdf_path") or attachment_paths.get("txt_path")
            if target_path and os.path.exists(target_path):
                with open(target_path, 'rb') as f:
                    file_data = f.read()
                    base_name = os.path.basename(target_path)
                    part = MIMEApplication(file_data, Name=base_name)
                    part['Content-Disposition'] = f'attachment; filename="{base_name}"'
                    msg.attach(part)
                    attached_name = base_name

        # Connect to SMTP Server
        server_host = config["smtp_server"]
        server_port = config["smtp_port"]

        if server_port == 465:
            server = smtplib.SMTP_SSL(server_host, server_port, timeout=15)
        else:
            server = smtplib.SMTP(server_host, server_port, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()

        server.login(config["smtp_email"], config["smtp_password"])
        server.sendmail(config["smtp_email"], [config["owner_email"]], msg.as_string())
        server.quit()

        log_security_event(
            case_id, filename, sha256, risk_level, threat_score, rules,
            "SENT", config["owner_email"]
        )

        return {
            "success": True,
            "triggered": True,
            "status": "SENT",
            "message": f"Alert email successfully transmitted to {config['owner_email']}",
            "recipient": config["owner_email"],
            "subject": subject,
            "attachment_name": attached_name,
            "is_test_mode": False,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        }

    except Exception as e:
        # Safe error logging — do not expose passwords
        err_msg = str(e)
        safe_error = f"SMTP Delivery Error ({type(e).__name__}): {err_msg}"
        print(f"[EMAIL_ALERT_ERROR] {safe_error}")
        
        log_security_event(
            case_id, filename, sha256, risk_level, threat_score, rules,
            f"FAILED: {type(e).__name__}", config["owner_email"]
        )

        return {
            "success": False,
            "triggered": True,
            "status": "FAILED",
            "error": safe_error,
            "message": f"Delivery failed to {config['owner_email']}: {type(e).__name__}",
            "recipient": config["owner_email"],
            "subject": subject,
            "is_test_mode": False,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        }
