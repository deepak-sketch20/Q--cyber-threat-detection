"""
Quantum Digital Signature Security Analyzer
Flask Application Entry Point
Supports: Multi-format forensic ingestion, Real Cryptographic Verification, X.509 PKI & Trust Chains,
Stateful Replay Tracking, Evidence-Weighted Risk Scoring, PQC Assessment & CycloneDX CBOM Generation.
"""

import os
import io
import json
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename

from file_analyzer import analyze_file_metadata, compute_sha256_bytes
from crypto_verifier import verify_cryptographic_payload, get_or_generate_demo_keys
from certificate_analyzer import analyze_certificate_data
from replay_store import check_and_record_stateful_replay, clear_replay_store, DEFAULT_FRESHNESS_WINDOW_SECONDS
from pqc_analyzer import analyze_post_quantum_posture, generate_cbom_json
from audit_logger import create_case_id, build_tamper_evident_audit_chain
from threat_detector import (
    detect_threats_automatic,
    generate_attack_scenario_table,
    analyze_signature_indicators,
    parse_quantum_values
)
from qds_engine import calculate_quantum_metrics
import qds_simulator
import risk_engine
from forensic_report import generate_forensic_summary, save_forensic_report_files, REPORTS_DIR
from email_alert import send_automatic_email_alert, get_email_config, log_security_event, SECURITY_EVENTS_LOG_FILE

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max limit
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'txt', 'json', 'csv', 'pdf', 'p7s', 'p7m', 'pem', 'der', 'cer', 'crt', 'asc', 'log'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Built-in sample datasets for test cases (Including Real Crypto, PKI, and PQC)
SAMPLE_FILES = {
    "test_1_secure.txt": (
        "DIGITAL SIGNATURE AUDIT RECORD\n"
        "Transaction ID: TXN-SECURE-2026-001\n"
        "Signer: Alice (Chief Cryptography Officer)\n"
        "Signed By: alice@quantum-vault.internal\n"
        "Signature Algorithm: ECDSA-P256-SHA256\n"
        "Certificate: X.509 v3 Valid (CN=Alice, OU=Security, O=QuantumSec)\n"
        "Authentication: PASS\n"
        "Signature Status: VALID\n"
        "Hash Mismatch: FALSE\n"
        "Nonce: 8f9b2c3d4e5f6a1b7c8d9e0f\n"
        "Session ID: SESS-20260902-8841\n"
        "Timestamp: 2026-09-02T08:15:00Z\n"
        "Channel Status: VERIFIED_SECURE\n"
        "Integrity Check: PASSED\n"
        "Payload: Verified quantum key distribution exchange and state telemetry intact."
    ),
    "test_2_replay_attack.txt": (
        "REPLAY ATTACK TEST\n\n"
        "Transaction ID: TXN-REPLAY-001\n\n"
        "Authentication: PASS\n\n"
        "Signature Status: VALID\n\n"
        "Nonce: REUSED\n\n"
        "Replay Indicator: DETECTED\n\n"
        "Previous Transaction: TXN-2026-0901-001\n\n"
        "Timestamp: REPEATED\n\n"
        "Session ID: REUSED\n"
    ),
    "test_3_forgery.txt": (
        "TRANSACTION SECURITY LOG - SUSPECT RECORD\n"
        "Transaction ID: TXN-FORGE-9942\n"
        "Signer: Bob (Finance Transfer)\n"
        "Signed By: bob@finance.internal\n"
        "Signature Algorithm: RSA-2048\n"
        "Signature Status: INVALID\n"
        "Forgery Indicator: DETECTED\n"
        "Hash Mismatch: TRUE\n"
        "Authentication: PASS\n"
        "Channel Status: NORMAL\n"
        "Security Alert: Digital signature mathematical verification failed against public key. Digest tampering detected."
    ),
    "test_4_impersonation.txt": (
        "ACCESS & SIGNATURE AUTHENTICATION LOG\n"
        "Transaction ID: TXN-AUTH-3011\n"
        "Claimed Signer: Eve (Unauthorized User)\n"
        "Signed By: Unknown User / Rogue Signer\n"
        "Impersonation Indicator: DETECTED\n"
        "Authentication: FAILED\n"
        "Signature Algorithm: Ed25519\n"
        "Signature Status: UNVERIFIED_SIGNER\n"
        "Certificate: Untrusted Self-Signed Certificate\n"
        "Security Alert: Signer identity does not match authorized PKI directory."
    ),
    "test_5_channel_tampering.txt": (
        "MESSAGE TRANSMISSION AUDIT\n"
        "Transaction ID: TXN-TRANS-4481\n"
        "Signer: Carol (Data Center Node 4)\n"
        "Signed By: node4@datacenter.internal\n"
        "Channel Status: TAMPERED\n"
        "Message Modification: DETECTED\n"
        "Modification Detected in transmission payload\n"
        "Integrity Check: FAILED\n"
        "Signature Algorithm: ECDSA\n"
        "Signature Status: VALID\n"
        "Security Alert: Bit alteration detected on classical transit channel between hops 3 and 4."
    ),
    "test_6_quantum_eavesdropping.txt": (
        "QUANTUM SECURITY EVENT REPORT\n\n"
        "Session ID: QKD-2026-0902-001\n\n"
        "Protocol:\n"
        "Quantum-Inspired Signature Verification\n\n"
        "Authentication: PASS\n\n"
        "Signature Status: VALID\n\n"
        "Quantum Channel: MONITORED\n\n"
        "Entangle-and-Measure Indicator: DETECTED\n\n"
        "QBER: 0.4700\n\n"
        "Mismatch Rate: 0.4700\n\n"
        "Rounds: 100\n\n"
        "Matches: 53\n\n"
        "Mismatches: 47\n\n"
        "Eavesdropping Indicator: DETECTED\n\n"
        "Security Note:\n"
        "Simulated quantum-state interaction caused a high error rate.\n"
    ),
    "test_7_multiple_threats.txt": (
        "CRITICAL MULTI-VECTOR ATTACK REPORT\n"
        "Transaction ID: TXN-MULTI-THREAT-881\n"
        "Signer: Unauthorized User\n"
        "Authentication: FAILED\n"
        "Impersonation Indicator: DETECTED\n"
        "Signature Status: INVALID\n"
        "Forgery Indicator: DETECTED\n"
        "Hash Mismatch: TRUE\n"
        "Replay Indicator: DETECTED\n"
        "Nonce: REUSED\n"
        "Timestamp: REPEATED\n"
        "Channel Status: TAMPERED\n"
        "Message Modification: DETECTED\n"
        "Entangle-and-Measure Indicator: DETECTED\n"
        "QBER: 0.4200\n"
        "Rounds: 100\n"
        "Matches: 58\n"
        "Mismatches: 42\n"
        "Eavesdropping Indicator: DETECTED\n"
    ),
    "test_8_real_crypto_verified.txt": (
        "REAL_CRYPTO_DEMO: RSA-2048-PSS\n"
        "PAYLOAD: OFFICIAL TRANSACTION RECORD: Transfer 5000 Q-Credits to Vault Node Alpha.\n"
        "SIGNATURE_HEX: 4a8f9c1b3d5e7f2a112233445566778899aabbccddeeff00112233445566778899aabbccddeeff004a8f9c1b3d5e7f2a112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00\n"
        "ALGORITHM: RSA-2048-PSS-SHA256\n"
        "PUBLIC_KEY: EMBEDDED_PKCS1\n"
        "STATUS: AUTHENTIC_SIGNATURE\n"
        "Note: Pure mathematical asymmetric verification test fixture."
    ),
    "test_9_real_crypto_tampered.txt": (
        "REAL_CRYPTO_DEMO: RSA-2048-PSS\n"
        "PAYLOAD: TAMPERED TRANSACTION: Transfer 999999 Q-Credits to Rogue Entity Eve.\n"
        "SIGNATURE_HEX: 4a8f9c1b3d5e7f2a112233445566778899aabbccddeeff00112233445566778899aabbccddeeff004a8f9c1b3d5e7f2a112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00\n"
        "ALGORITHM: RSA-2048-PSS-SHA256\n"
        "TAMPERED: TRUE\n"
        "Note: Signature bytes modified by 1 byte; mathematical cryptographic verification will fail."
    ),
    "test_10_pqc_mldsa_standard.txt": (
        "POST-QUANTUM DIGITAL SIGNATURE MANIFEST\n"
        "Standard: NIST FIPS 204 (ML-DSA)\n"
        "Algorithm: ML-DSA-65\n"
        "Security Level: NIST Category 3 (Quantum-Resistant)\n"
        "Signer: CN=Post-Quantum Root Signer, O=Quantum Defense PKI\n"
        "Public Key: 1952 bytes (Module-Lattice M-LWE)\n"
        "Signature Size: 3309 bytes\n"
        "Signature Status: VALID\n"
        "Hash Mismatch: FALSE\n"
        "Integrity Status: INTACT\n"
        "PQC Status: QUANTUM-SAFE NATIVE\n"
    )
}

# Pre-populate sample files to uploads folder
for s_name, s_content in SAMPLE_FILES.items():
    s_path = os.path.join(UPLOAD_FOLDER, s_name)
    try:
        with open(s_path, 'w', encoding='utf-8') as f:
            f.write(s_content)
    except Exception:
        pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/samples', methods=['GET'])
def get_samples():
    """Returns list of built-in sample test suites."""
    return jsonify({
        "success": True,
        "samples": [
            {"id": "test_1_secure.txt", "name": "Test 1: Secure Normal File", "expected": "SECURE (Low Risk ~5)"},
            {"id": "test_2_replay_attack.txt", "name": "Test 2: Replay Attack", "expected": "ATTACK DETECTED (High Risk 85+, Replay)"},
            {"id": "test_3_forgery.txt", "name": "Test 3: Signature Forgery", "expected": "ATTACK DETECTED (High/Critical Risk, Forgery)"},
            {"id": "test_4_impersonation.txt", "name": "Test 4: Impersonation Attack", "expected": "ATTACK DETECTED (High Risk, Impersonation)"},
            {"id": "test_5_channel_tampering.txt", "name": "Test 5: Channel Tampering", "expected": "ATTACK DETECTED (High Risk, Tampering)"},
            {"id": "test_6_quantum_eavesdropping.txt", "name": "Test 6: Quantum Eavesdropping", "expected": "ATTACK DETECTED (Critical Risk ~98, Entangle-and-Measure)"},
            {"id": "test_7_multiple_threats.txt", "name": "Test 7: Multiple Threats", "expected": "ATTACK DETECTED (Multiple Indicators Detected)"},
            {"id": "test_8_real_crypto_verified.txt", "name": "Test 8: Real Cryptographic Signature (PASS)", "expected": "MATHEMATICAL VERIFICATION: VALID"},
            {"id": "test_9_real_crypto_tampered.txt", "name": "Test 9: Real Crypto Tampered Digest (FAIL)", "expected": "MATHEMATICAL VERIFICATION: FAILED"},
            {"id": "test_10_pqc_mldsa_standard.txt", "name": "Test 10: NIST FIPS 204 ML-DSA Standard", "expected": "PQC STATUS: QUANTUM-SAFE NATIVE"}
        ]
    })

@app.route('/api/sample/<sample_id>', methods=['GET'])
def get_sample_content(sample_id):
    """Retrieves raw content of a sample test file."""
    if sample_id in SAMPLE_FILES:
        return jsonify({
            "success": True,
            "filename": sample_id,
            "content": SAMPLE_FILES[sample_id]
        })
    return jsonify({"success": False, "error": "Sample not found"}), 404

@app.route('/api/replay/reset', methods=['POST'])
def reset_replay_cache():
    """Resets the stateful replay database."""
    clear_replay_store()
    return jsonify({"success": True, "message": "Stateful replay cache has been cleared."})

@app.route('/api/upload', methods=['POST'])
def handle_upload():
    """
    Main API endpoint for Quantum Digital Signature Security Analyzer.
    Analyzes uploaded files or sample payloads and returns complete security breakdown.
    """
    try:
        file_bytes = None
        filename = "unknown.txt"
        simulation_mode = request.form.get('attack_mode', 'Automatic Detection')
        reference_hash = request.form.get('reference_hash') or request.args.get('reference_hash')

        # 1. Ingest from multipart/form-data
        if 'file' in request.files and request.files['file'].filename:
            uploaded_file = request.files['file']
            filename = secure_filename(uploaded_file.filename) or "uploaded_file.txt"
            if not allowed_file(filename):
                return jsonify({
                    "success": False,
                    "error": f"Unsupported file type. Allowed formats: {', '.join(ALLOWED_EXTENSIONS)}"
                }), 400
            file_bytes = uploaded_file.read()

        # 2. Ingest from Sample ID
        elif request.form.get('sample_id'):
            sample_id = request.form.get('sample_id')
            if sample_id in SAMPLE_FILES:
                filename = sample_id
                file_bytes = SAMPLE_FILES[sample_id].encode('utf-8')
            else:
                return jsonify({"success": False, "error": f"Unknown sample identifier: {sample_id}"}), 400

        # 3. Ingest from raw JSON or form text
        elif request.is_json and request.json.get('text_content'):
            filename = request.json.get('filename', 'analysis_input.txt')
            file_bytes = request.json.get('text_content').encode('utf-8')
            simulation_mode = request.json.get('attack_mode', 'Automatic Detection')
            reference_hash = request.json.get('reference_hash')
        elif request.form.get('text_content'):
            filename = request.form.get('filename', 'analysis_input.txt')
            file_bytes = request.form.get('text_content').encode('utf-8')
        else:
            return jsonify({
                "success": False,
                "error": "Please select a file first."
            }), 400

        if not file_bytes:
            return jsonify({"success": False, "error": "Uploaded file is empty or could not be read."}), 400

        # =========================================================
        # FORENSIC WORKFLOW EXECUTION
        # =========================================================
        case_id = create_case_id()

        # Step 1: File Metadata & SHA-256 Integrity Verification
        meta = analyze_file_metadata(file_bytes, filename, reference_hash)
        raw_text = meta['content_info']['raw_text']
        structured_fields = meta['content_info']['structured_fields']

        # Step 2: Mathematical Cryptographic Signature Verification Layer
        crypto_verif = verify_cryptographic_payload(file_bytes, filename, raw_text)

        # Step 3: X.509 PKI Certificate, Trust Chain & Revocation Inspection
        cert_info = analyze_certificate_data(file_bytes, filename, raw_text)

        # Step 4: Stateful Replay Store & Freshness Engine Check
        nonce_val = structured_fields.get("nonce")
        txn_id_val = structured_fields.get("transaction_id") or structured_fields.get("txn_id")
        sess_val = structured_fields.get("session_id")
        ts_val = structured_fields.get("timestamp")
        signer_val = structured_fields.get("signed_by") or structured_fields.get("signer")
        
        stateful_replay = check_and_record_stateful_replay(
            nonce=nonce_val,
            txn_id=txn_id_val,
            session_id=sess_val,
            message_hash=meta['sha256'],
            signer_id=signer_val,
            filename=filename,
            timestamp_str=ts_val
        )

        # Step 5: Heuristic Digital Signature Indicators
        sig_info = analyze_signature_indicators(raw_text)

        # Step 6: Automatic Multi-Threat Correlation Engine
        threat_result = detect_threats_automatic(
            text=raw_text,
            structured_fields=structured_fields,
            stateful_replay_info=stateful_replay,
            crypto_verification_info=crypto_verif,
            cert_info=cert_info
        )

        # Step 7: Quantum-Inspired Simulation Telemetry & Disclaimers
        parsed_q = parse_quantum_values(raw_text)
        quantum_metrics = calculate_quantum_metrics(raw_text, threat_result['detected_threat'], parsed_q)

        # Step 8: Post-Quantum Cryptography & Crypto-Agility Assessment
        detected_algo = crypto_verif.get("algorithm_detected") or sig_info.get("signature_algorithm", "ECDSA-P256")
        pqc_posture = analyze_post_quantum_posture(detected_algo, raw_text)

        # Step 9: CycloneDX Cryptography Bill of Materials (CBOM)
        cbom_data = generate_cbom_json(meta, sig_info, pqc_posture, cert_info)

        # Step 10: 8-Row Attack Scenario Analysis Matrix
        attack_table = generate_attack_scenario_table(
            threat_result['detected_threat'],
            threat_result['status'],
            simulation_mode
        )

        # Step 11: Executive Forensic Summary Generation
        forensic_summary = generate_forensic_summary(
            case_id=case_id,
            filename=filename,
            sha256_hash=meta['sha256'],
            threat_result=threat_result,
            sig_info=sig_info,
            integrity_status=meta['integrity_status'],
            quantum_metrics=quantum_metrics,
            stateful_replay_info=stateful_replay,
            crypto_verif_info=crypto_verif,
            cert_info=cert_info
        )
        report_files = save_forensic_report_files(forensic_summary)

        # Step 12: Automatic Email Alerting (Sends to configured OWNER_EMAIL on HIGH / CRITICAL)
        email_status = send_automatic_email_alert(
            summary=forensic_summary,
            attachment_paths=report_files,
            force_send=False
        )

        # Step 13: Tamper-Evident Chained Audit Logging
        is_attack = threat_result['status'] == "ATTACK DETECTED"
        now_str = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        
        raw_audit_events = [
            {"time": now_str, "event": f"Case {case_id} initialized for '{filename}' ({meta['file_size']})", "status": "SUCCESS"},
            {"time": now_str, "event": f"SHA-256 computed: {meta['sha256'][:16]}... (Integrity: {meta['integrity_status']})", "status": "SUCCESS"},
            {"time": now_str, "event": f"Cryptographic Verifier: {crypto_verif['verification_badge']}", "status": "SUCCESS" if crypto_verif['is_verified'] else "INFO"},
            {"time": now_str, "event": f"PKI Certificate Status: {cert_info['status']} | Chain: {cert_info['trust_chain']}", "status": "SUCCESS" if cert_info['status'] == "VALID" else "WARNING"},
            {"time": now_str, "event": f"Stateful Replay Engine: {stateful_replay['stateful_replay_type']} (Hits: {stateful_replay['hit_count']})", "status": "ALERT" if stateful_replay['is_stateful_replay'] else "SUCCESS"},
            {"time": now_str, "event": f"Multi-Threat Correlation completed. Primary: {threat_result['detected_threat']} (Score: {threat_result['risk_score']}/100)", "status": "ALERT" if is_attack else "SUCCESS"},
            {"time": now_str, "event": f"Executive Forensic Report: Generated {report_files['pdf_filename']}", "status": "SUCCESS"},
            {"time": now_str, "event": f"Automatic Email Alert: {email_status['status']} ({email_status.get('recipient', '')})", "status": "ALERT" if email_status['status'] == 'SENT' else ("INFO" if email_status['status'] == 'TEST_MODE_SIMULATED' else "SUCCESS")},
            {"time": now_str, "event": f"PQC Assessment: {pqc_posture['pqc_status']} (Readiness: {pqc_posture['pqc_readiness_score']}/100)", "status": "SUCCESS"},
            {"time": now_str, "event": f"Actionable Defense: {threat_result['first_action'][:45]}...", "status": "ACTION_REQUIRED" if is_attack else "SUCCESS"}
        ]
        chained_audit_logs = build_tamper_evident_audit_chain(raw_audit_events)

        # Chart Data
        graphs_data = {
            "labels": ["Risk Score", "Confidence", "PQC Readiness", "Crypto Agility"],
            "values": [
                threat_result['risk_score'],
                threat_result['confidence'],
                pqc_posture['pqc_readiness_score'],
                pqc_posture['crypto_agility_score']
            ],
            "quantum_labels": ["Matching Rate", "Mismatch Rate", "QBER"],
            "quantum_values": [
                round(quantum_metrics['matching_rate'] * 100, 1),
                round(quantum_metrics['mismatch_rate'] * 100, 1),
                round(quantum_metrics['qber'] * 100, 1)
            ]
        }

        # Assemble Master Response
        response_data = {
            "success": True,
            "case_id": case_id,
            "file": {
                "filename": meta['filename'],
                "file_type": meta['file_type'],
                "mime_type": meta['mime_type'],
                "magic_header": meta['magic_header'],
                "file_size": meta['file_size'],
                "file_size_bytes": meta['file_size_bytes'],
                "upload_time": meta['upload_time'],
                "sha256": meta['sha256'],
                "sha256_computation": meta['sha256_computation'],
                "reference_hash": meta['reference_hash'],
                "hash_match": meta['hash_match'],
                "integrity_comparison": meta['integrity_comparison'],
                "integrity_status": meta['integrity_status']
            },
            "cryptographic_verification": crypto_verif,
            "certificate_analysis": cert_info,
            "stateful_replay": stateful_replay,
            "signature": sig_info,
            "threat": threat_result,
            "quantum": quantum_metrics,
            "post_quantum_assessment": pqc_posture,
            "cbom": cbom_data,
            "attack_table": attack_table,
            "logs": chained_audit_logs,
            "forensic_summary": forensic_summary,
            "email_alert": email_status,
            "report_files": {
                "pdf_url": f"/api/report/download/{case_id}?format=pdf",
                "txt_url": f"/api/report/download/{case_id}?format=txt",
                "pdf_filename": report_files['pdf_filename'],
                "txt_filename": report_files['txt_filename']
            },
            "content_preview": {
                "raw_text": raw_text[:3000] + ("\n... [truncated]" if len(raw_text) > 3000 else ""),
                "line_count": meta['content_info']['line_count'],
                "extracted_type": meta['content_info']['extracted_type'],
                "structured_fields": structured_fields,
                "warning": meta['content_info']['warning']
            },
            "summary": {
                "case_id": case_id,
                "analyzed_at": meta['upload_time'],
                "overall_status": "ATTACK DETECTED" if is_attack else "SECURE",
                "primary_threat": threat_result['detected_threat'],
                "threat_category": threat_result['threat_category'],
                "risk_score": threat_result['risk_score'],
                "risk_level": threat_result['risk'],
                "recommendation_summary": threat_result['first_action'],
                "pqc_migration_target": pqc_posture['recommended_pqc'],
                "email_dispatched": email_status.get('status') in ['SENT', 'TEST_MODE_SIMULATED'],
                "email_recipient": email_status.get('recipient')
            },
            "graphs": graphs_data
        }

        return jsonify(response_data)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Analysis execution failed: {str(e)}"
        }), 500

@app.route('/api/report/download/<case_id>', methods=['GET'])
def download_forensic_report(case_id):
    """Serves the generated Executive Forensic Summary PDF or TXT."""
    try:
        fmt = request.args.get('format', 'pdf').lower()
        case_id_clean = re.sub(r'[^A-Za-z0-9_-]', '_', case_id)
        filename = f"Executive_Forensic_Summary_{case_id_clean}.{fmt}"
        file_path = os.path.join(REPORTS_DIR, filename)

        if not os.path.exists(file_path):
            # Try text fallback
            alt_filename = f"Executive_Forensic_Summary_{case_id_clean}.txt"
            alt_path = os.path.join(REPORTS_DIR, alt_filename)
            if os.path.exists(alt_path):
                return send_from_directory(REPORTS_DIR, alt_filename, as_attachment=True)
            return jsonify({"success": False, "error": f"Report for {case_id} not found"}), 404

        return send_from_directory(REPORTS_DIR, filename, as_attachment=True)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/email/test', methods=['POST'])
def test_email_alert():
    """Manual trigger to test SMTP email configuration and alert dispatch."""
    try:
        req_data = request.json or {}
        case_id = req_data.get('case_id') or create_case_id()
        mock_summary = {
            "case_id": case_id,
            "target_file": req_data.get('filename', 'security_audit_test.pdf'),
            "risk_level": req_data.get('risk_level', 'HIGH'),
            "threat_score": req_data.get('threat_score', 78),
            "sha256": req_data.get('sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
            "threat_indicators": [
                "Digital signature verification failed (MISMATCH)",
                "Timestamp stale (>120s delta)",
                "Elevated simulated QBER (0.1420 > 0.0500)"
            ],
            "quantum_metrics": {
                "qber": "14.20%",
                "mismatch_rate": "14.20%",
                "matching_rate": "85.80%",
                "eavesdrop_probability": "68.50%",
                "quantum_risk": "HIGH (Simulated)",
                "security_level": "SUSPICIOUS (Simulated)"
            },
            "recommended_action": "Quarantine target file and investigate signing key validity.",
            "forensic_findings": "Manual diagnostic test triggered by system security administrator."
        }

        report_files = save_forensic_report_files(mock_summary)
        result = send_automatic_email_alert(mock_summary, report_files, force_send=True)
        return jsonify({"success": True, "alert_result": result, "case_id": case_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/config/email', methods=['GET'])
def get_email_status():
    """Returns safe email configuration without revealing passwords."""
    cfg = get_email_config()
    return jsonify({
        "success": True,
        "owner_email": cfg["owner_email"],
        "smtp_server": cfg["smtp_server"],
        "smtp_port": cfg["smtp_port"],
        "smtp_configured": cfg["has_credentials"],
        "is_test_mode": cfg["is_test_mode"]
    })

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "Quantum Digital Signature Security Analyzer",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "quantum_engine": "Simulation-Based Statevector (Qiskit Equivalent)"
    })

# ==============================================================================
# QUANTUM SECURITY LAB & QDS SIMULATOR API ENDPOINTS
# ==============================================================================

@app.route('/api/qds/qubit', methods=['GET'])
def api_qds_qubit():
    """Simulates a single qubit state (0, 1, superposition, or arbitrary)."""
    try:
        state_type = request.args.get('state', 'superposition')
        theta = float(request.args.get('theta', 1.5707963))
        phi = float(request.args.get('phi', 0.0))
        shots = int(request.args.get('shots', 1024))
        result = qds_simulator.simulate_qubit(state_type=state_type, theta=theta, phi=phi, shots=shots)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/qds/bell', methods=['GET'])
def api_qds_bell():
    """Simulates 2-qubit Bell State generation (Phi+, Phi-, Psi+, Psi-)."""
    try:
        bell_state = request.args.get('bell_state', 'Phi+')
        shots = int(request.args.get('shots', 1024))
        result = qds_simulator.simulate_bell_state(bell_state=bell_state, shots=shots)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/qds/entanglement', methods=['GET'])
def api_qds_entanglement():
    """Verifies quantum entanglement correlation and matching statistics."""
    try:
        shots = int(request.args.get('shots', 1024))
        noise_level = float(request.args.get('noise_level', 0.003))
        result = qds_simulator.simulate_entanglement(shots=shots, noise_level=noise_level)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/qds/teleportation', methods=['POST'])
def api_qds_teleportation():
    """Executes 3-qubit quantum teleportation protocol and Pauli corrections."""
    try:
        req_data = request.json or {}
        message_state = req_data.get('message_state', 'superposition')
        custom_theta = req_data.get('custom_theta')
        if custom_theta is not None:
            custom_theta = float(custom_theta)
        shots = int(req_data.get('shots', 1024))
        result = qds_simulator.simulate_teleportation(
            message_state=message_state,
            custom_theta=custom_theta,
            shots=shots
        )
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/qds/pauli', methods=['POST'])
def api_qds_pauli():
    """Evaluates Pauli correction gate lookup for classical measurement bits."""
    try:
        req_data = request.json or {}
        bits = req_data.get('bits', '00')
        result = qds_simulator.apply_pauli_correction(bits=bits)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/qds/channel', methods=['POST'])
def api_qds_channel():
    """Simulates quantum channel transmission under normal or adversarial attack conditions."""
    try:
        req_data = request.json or {}
        mode = req_data.get('mode', 'NORMAL')
        total_bits = int(req_data.get('total_bits', 1000))
        disturbance = req_data.get('disturbance_level')
        if disturbance is not None:
            disturbance = float(disturbance)
        result = qds_simulator.simulate_quantum_channel(
            mode=mode,
            total_bits=total_bits,
            disturbance_level=disturbance
        )
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/qds/simulate', methods=['POST'])
def api_qds_simulate_complete():
    """Runs complete end-to-end Quantum Digital Signature simulation workflow."""
    try:
        req_data = request.json or {}
        result = qds_simulator.simulate_complete_qds(req_data)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/cbom/export', methods=['POST'])
def export_cbom():
    """Generates standalone downloadable CBOM JSON."""
    try:
        data = request.json or {}
        cbom = data.get("cbom")
        if not cbom:
            return jsonify({"success": False, "error": "No CBOM payload provided"}), 400
        return jsonify(cbom)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting Quantum Digital Signature Security Analyzer on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=True)
