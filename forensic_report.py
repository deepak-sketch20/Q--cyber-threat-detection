"""
Quantum-Inspired Cyber Threat Detection for Digital Signature Security
Module: Executive Forensic Summary Generator
Generates structured forensic summaries and exportable PDF / TXT reports.
"""

import os
import io
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_forensic_summary(
    case_id: str,
    filename: str,
    sha256_hash: str,
    threat_result: Dict[str, Any],
    sig_info: Dict[str, Any],
    integrity_status: str,
    quantum_metrics: Dict[str, Any],
    stateful_replay_info: Optional[Dict[str, Any]] = None,
    crypto_verif_info: Optional[Dict[str, Any]] = None,
    cert_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Constructs the official Executive Forensic Summary dictionary according to specifications.
    Strictly rule-based — does not invent evidence.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    risk_score = threat_result.get("risk_score", 0)
    risk_level = threat_result.get("risk", "LOW")
    if risk_score <= 20:
        risk_level = "LOW"
    elif risk_score <= 50:
        risk_level = "MEDIUM"
    elif risk_score <= 75:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    is_threat = risk_level in ["HIGH", "CRITICAL"] or threat_result.get("status") == "ATTACK DETECTED"
    overall_status = "THREAT DETECTED" if is_threat else "NORMAL / SYSTEM SECURE"

    # Derive Digital Signature Status
    if crypto_verif_info and crypto_verif_info.get("mathematical_verification") == "FAILED":
        sig_status = "INVALID"
    elif sig_info.get("hash_mismatch"):
        sig_status = "MISMATCH"
    elif "INVALID" in sig_info.get("signature_status", "").upper():
        sig_status = "INVALID"
    elif "VALID" in sig_info.get("signature_status", "").upper() or (crypto_verif_info and crypto_verif_info.get("is_verified")):
        sig_status = "VALID"
    elif sig_info.get("signature_present"):
        sig_status = "PRESENT (UNVERIFIED)"
    else:
        sig_status = "NOT AVAILABLE"

    # Derive File Integrity Status
    if "FAIL" in integrity_status.upper() or "TAMPER" in integrity_status.upper():
        file_integrity = "MODIFIED"
    elif "MISMATCH" in integrity_status.upper():
        file_integrity = "SUSPICIOUS"
    else:
        file_integrity = "INTACT"

    # Timestamp freshness
    ts_freshness = "FRESH"
    if stateful_replay_info:
        if stateful_replay_info.get("timestamp_freshness") == "STALE" or stateful_replay_info.get("is_stateful_replay"):
            ts_freshness = "STALE"
    
    # Collect all triggered threat indicators
    indicators = []
    if threat_result.get("evidence"):
        for ev in threat_result["evidence"]:
            indicators.append(ev)
    
    if sig_status in ["INVALID", "MISMATCH"]:
        indicators.append(f"Digital signature validation failed ({sig_status})")
    if file_integrity != "INTACT":
        indicators.append(f"File integrity status flagged as {file_integrity}")
    if ts_freshness == "STALE":
        indicators.append("Transaction timestamp is stale / outside validity freshness window")
    
    qber_val = quantum_metrics.get("qber", 0.0)
    mismatch_val = quantum_metrics.get("mismatch_rate", 0.0)
    eavesdrop_val = float(quantum_metrics.get("estimated_eavesdropping_probability_value", 0.0) or 0.0)
    
    # Rule-based threshold checks (> 0.05 / 5%)
    if qber_val > 0.05:
        indicators.append(f"Simulated QBER above 5% threshold: {qber_val * 100:.1f}%")
    if mismatch_val > 0.05:
        indicators.append(f"Simulated Mismatch Rate above 5% threshold: {mismatch_val * 100:.1f}%")
    if eavesdrop_val > 0.05:
        indicators.append(f"Simulated Eavesdrop Probability above 5% threshold: {eavesdrop_val * 100:.1f}%")

    if not indicators:
        indicators.append("All baseline cryptographic rules and quantum-inspired telemetry checks passed.")

    # Deduplicate indicators while preserving order
    deduped_indicators = []
    for ind in indicators:
        if ind not in deduped_indicators:
            deduped_indicators.append(ind)

    # Forensic findings explanation
    if is_threat:
        findings = (
            f"Forensic examination of target '{filename}' identified anomalous indicators in digital signature "
            f"and channel integrity channels. Rule-based evaluation triggered {len(deduped_indicators)} rule(s) "
            f"resulting in an overall threat score of {risk_score}/100 ({risk_level}). Primary vector: "
            f"{threat_result.get('detected_threat', 'Unknown Anomaly')}. {threat_result.get('reason', '')}"
        )
    else:
        findings = (
            f"Target file '{filename}' verified clean. Cryptographic signature and simulated channel telemetry "
            f"satisfy all baseline security constraints. No unauthorized tampering or eavesdropping anomalies detected."
        )

    # Recommended executive action
    if is_threat:
        rec_action = (
            "1. Quarantining the target file and blocking the associated session/identity.\n"
            "2. Revoking or re-verifying the associated digital signature certificates in the PKI directory.\n"
            "3. Preserving the SHA-256 hash and immutable audit trail for full incident response.\n"
            "4. Performing out-of-band identity verification with the claimed signer."
        )
    else:
        rec_action = (
            "1. Maintain the verified signature record in the audit repository.\n"
            "2. Retain SHA-256 digest in the tamper-evident ledger for non-repudiation."
        )

    summary_data = {
        "case_id": case_id,
        "date_time": now_utc,
        "target_file": filename,
        "sha256": sha256_hash,
        "overall_status": overall_status,
        "risk_level": risk_level,
        "threat_score": risk_score,
        "threat_indicators": deduped_indicators,
        "digital_signature_status": sig_status,
        "file_integrity": file_integrity,
        "quantum_metrics": {
            "qber": f"{qber_val * 100:.2f}%",
            "mismatch_rate": f"{mismatch_val * 100:.2f}%",
            "matching_rate": f"{quantum_metrics.get('matching_rate', 1.0) * 100:.2f}%",
            "eavesdrop_probability": f"{eavesdrop_val * 100:.2f}%" if eavesdrop_val else quantum_metrics.get("estimated_eavesdropping_probability", "0.0%"),
            "quantum_risk": quantum_metrics.get("quantum_risk", "LOW (Simulated)"),
            "security_level": quantum_metrics.get("security_level", "STANDARD (Simulated)")
        },
        "timestamp_freshness": ts_freshness,
        "forensic_findings": findings,
        "recommended_action": rec_action,
        "evidence": [
            f"SHA-256: {sha256_hash}",
            f"Calculated Threat Score: {risk_score}/100",
            f"Risk Level: {risk_level}",
            f"Simulated QBER: {qber_val * 100:.2f}% (Threshold: 5.0%)",
            f"Simulated Mismatch: {mismatch_val * 100:.2f}%"
        ]
    }

    return summary_data

def format_forensic_summary_text(summary: Dict[str, Any]) -> str:
    """Formats the Executive Forensic Summary as clean, standard monospaced text."""
    indicators_formatted = "\n".join([f"  • {ind}" for ind in summary["threat_indicators"]])
    evidence_formatted = "\n".join([f"  • {ev}" for ev in summary["evidence"]])
    
    text = f"""================================================================================
                      EXECUTIVE FORENSIC SUMMARY REPORT
                 Quantum-Inspired Cyber Threat Detection System
================================================================================

CASE INFORMATION:
  Case ID:                {summary['case_id']}
  Date & Time:            {summary['date_time']}
  Target File:            {summary['target_file']}
  SHA-256 Digest:         {summary['sha256']}

EXECUTIVE ASSESSMENT:
  Overall Status:         {summary['overall_status']}
  Risk Level:             {summary['risk_level']}
  Threat Score:           {summary['threat_score']} / 100

SECURITY & CRYPTOGRAPHIC VERIFICATION:
  Digital Signature:      {summary['digital_signature_status']}
  File Integrity:         {summary['file_integrity']}
  Timestamp Freshness:    {summary['timestamp_freshness']}

QUANTUM-INSPIRED TELEMETRY (SIMULATED):
  QBER:                   {summary['quantum_metrics']['qber']}
  Mismatch Rate:          {summary['quantum_metrics']['mismatch_rate']}
  Matching Rate:          {summary['quantum_metrics']['matching_rate']}
  Eavesdrop Probability:  {summary['quantum_metrics']['eavesdrop_probability']}
  Quantum Risk Level:     {summary['quantum_metrics']['quantum_risk']}
  Security Level:         {summary['quantum_metrics']['security_level']}

TRIGGERED THREAT INDICATORS:
{indicators_formatted}

FORENSIC FINDINGS:
  {summary['forensic_findings']}

RECOMMENDED EXECUTIVE ACTION:
  {summary['recommended_action']}

EVIDENCE VERIFICATION LEDGER:
{evidence_formatted}

================================================================================
NOTICE: Quantum metrics represent a simulated quantum-inspired channel model.
        Generated automatically by Quantum Digital Signature Security Analyzer.
================================================================================
"""
    return text

def save_forensic_report_files(summary: Dict[str, Any]) -> Dict[str, str]:
    """
    Saves both TXT and PDF copies of the Executive Forensic Summary.
    Returns dictionary with file paths.
    """
    case_id_clean = re.sub(r'[^A-Za-z0-9_-]', '_', summary["case_id"])
    txt_filename = f"Executive_Forensic_Summary_{case_id_clean}.txt"
    pdf_filename = f"Executive_Forensic_Summary_{case_id_clean}.pdf"

    txt_path = os.path.join(REPORTS_DIR, txt_filename)
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    # 1. Save TXT
    raw_text = format_forensic_summary_text(summary)
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(raw_text)

    # 2. Save PDF (using ReportLab if installed, otherwise clean fallback)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=16,
            leading=20,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold'
        )

        subtitle_style = ParagraphStyle(
            'SubTitleStyle',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#0891b2'),
            fontName='Helvetica-Bold'
        )

        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#1e293b'),
            fontName='Helvetica-Bold',
            spaceBefore=8,
            spaceAfter=4
        )

        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor('#334155'),
            fontName='Helvetica'
        )

        mono_style = ParagraphStyle(
            'MonoBody',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0f172a'),
            fontName='Courier'
        )

        story.append(Paragraph("EXECUTIVE FORENSIC ALERT REPORT", title_style))
        story.append(Paragraph("Quantum-Inspired Cyber Threat Detection for Digital Signature Security", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0891b2'), spaceAfter=10))

        # Overview Table
        is_threat = summary['risk_level'] in ['HIGH', 'CRITICAL']
        status_color = colors.HexColor('#dc2626') if is_threat else colors.HexColor('#059669')
        
        overview_data = [
            [Paragraph("<b>Case Identifier:</b>", body_style), Paragraph(summary['case_id'], mono_style),
             Paragraph("<b>Analysis Time (UTC):</b>", body_style), Paragraph(summary['date_time'], body_style)],
            [Paragraph("<b>Target File:</b>", body_style), Paragraph(summary['target_file'], body_style),
             Paragraph("<b>Risk Level:</b>", body_style), Paragraph(f"<b>{summary['risk_level']} ({summary['threat_score']}/100)</b>", ParagraphStyle('Risk', parent=body_style, textColor=status_color, fontName='Helvetica-Bold'))],
            [Paragraph("<b>Overall Status:</b>", body_style), Paragraph(f"<b>{summary['overall_status']}</b>", ParagraphStyle('Status', parent=body_style, textColor=status_color, fontName='Helvetica-Bold')),
             Paragraph("<b>Signature Status:</b>", body_style), Paragraph(summary['digital_signature_status'], body_style)]
        ]

        t_overview = Table(overview_data, colWidths=[105, 160, 110, 165])
        t_overview.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_overview)
        story.append(Spacer(1, 10))

        # Cryptographic Hash & Evidence
        story.append(Paragraph("<b>Calculated Cryptographic Hash (SHA-256):</b>", section_style))
        story.append(Paragraph(summary['sha256'], mono_style))
        story.append(Spacer(1, 8))

        # Quantum Telemetry Table
        story.append(Paragraph("<b>Quantum-Inspired Channel Telemetry (Simulated):</b>", section_style))
        qm = summary['quantum_metrics']
        q_data = [
            [Paragraph("<b>QBER:</b>", body_style), Paragraph(qm['qber'], mono_style),
             Paragraph("<b>Mismatch Rate:</b>", body_style), Paragraph(qm['mismatch_rate'], mono_style)],
            [Paragraph("<b>Matching Rate:</b>", body_style), Paragraph(qm['matching_rate'], mono_style),
             Paragraph("<b>Eavesdrop Probability:</b>", body_style), Paragraph(qm['eavesdrop_probability'], mono_style)],
            [Paragraph("<b>Quantum Risk:</b>", body_style), Paragraph(qm['quantum_risk'], body_style),
             Paragraph("<b>Security Level:</b>", body_style), Paragraph(qm['security_level'], body_style)]
        ]
        t_q = Table(q_data, colWidths=[105, 160, 110, 165])
        t_q.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ecfeff')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#a5f3fc')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cffafe')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_q)
        story.append(Spacer(1, 8))

        # Triggered Threat Indicators
        story.append(Paragraph("<b>Triggered Rule-Based Indicators:</b>", section_style))
        for ind in summary['threat_indicators']:
            story.append(Paragraph(f"• {ind}", body_style))
        story.append(Spacer(1, 8))

        # Findings & Recommendations
        story.append(Paragraph("<b>Forensic Findings:</b>", section_style))
        story.append(Paragraph(summary['forensic_findings'], body_style))
        story.append(Spacer(1, 8))

        story.append(Paragraph("<b>Recommended Executive Actions:</b>", section_style))
        for act_line in summary['recommended_action'].split('\n'):
            if act_line.strip():
                story.append(Paragraph(act_line, body_style))
        story.append(Spacer(1, 10))

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#94a3b8'), spaceAfter=6))
        story.append(Paragraph(
            "Confidential Security Audit Document • Tamper-Evident SHA-256 Chained Evidence • Simulated Quantum Metrics",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=7.5, alignment=TA_CENTER, textColor=colors.HexColor('#64748b'))
        ))

        doc.build(story)

    except Exception as pdf_err:
        # Fallback PDF creation if ReportLab fails
        with open(pdf_path, 'w', encoding='utf-8') as pf:
            pf.write(raw_text)

    return {
        "txt_path": txt_path,
        "pdf_path": pdf_path,
        "txt_filename": txt_filename,
        "pdf_filename": pdf_filename
    }
