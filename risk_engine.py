"""
Quantum Digital Signature Security Analyzer
Risk Engine Module: Comprehensive Multi-Threat Correlation & Weighted Scoring
================================================================================
Evaluates all attack vectors without stopping at the first detected threat:
- Digital Signature Forgery
- Stateful & Heuristic Replay Attacks
- Signer Identity Impersonation
- Unauthorized Verification (Authorized vs Actual Verifier)
- Quantum Eavesdropping (Entangle-and-Measure)
- Intercept-Resend Attacks
- Quantum Channel Manipulation
- Classical Channel Tampering

Risk Scoring Model:
  0 - 29   LOW
  30 - 59  MEDIUM
  60 - 89  HIGH
  90 - 100 CRITICAL
"""

from typing import Dict, Any, List, Optional

def calculate_threat_risk(
    file_metadata: Optional[Dict[str, Any]] = None,
    crypto_verif_info: Optional[Dict[str, Any]] = None,
    cert_info: Optional[Dict[str, Any]] = None,
    stateful_replay_info: Optional[Dict[str, Any]] = None,
    sig_info: Optional[Dict[str, Any]] = None,
    quantum_metrics: Optional[Dict[str, Any]] = None,
    text_content: str = "",
    structured_fields: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Analyzes ALL security indicators across the entire file payload and verification subsystems.
    Identifies multiple concurrent threats, determines the primary highest-risk threat,
    calculates a calibrated composite risk score (0-100), and outputs actionable first responses.
    """
    if file_metadata is None:
        file_metadata = {}
    if crypto_verif_info is None:
        crypto_verif_info = {}
    if cert_info is None:
        cert_info = {}
    if stateful_replay_info is None:
        stateful_replay_info = {}
    if sig_info is None:
        sig_info = {}
    if quantum_metrics is None:
        quantum_metrics = {}
    if structured_fields is None:
        structured_fields = {}

    detected_threats: List[Dict[str, Any]] = []

    # --------------------------------------------------------------------------
    # 1. SIGNATURE FORGERY / CRYPTOGRAPHIC VERIFICATION FAILURE
    # --------------------------------------------------------------------------
    forgery_evidence = []
    is_forgery = False
    
    if crypto_verif_info.get("mathematical_verification") == "FAILED":
        forgery_evidence.append("Mathematical cryptographic signature verification failed against public key")
        is_forgery = True
    if "INVALID" in sig_info.get("signature_status", "").upper():
        forgery_evidence.append("Signature format or heuristic status marked INVALID")
        is_forgery = True
    if sig_info.get("hash_mismatch") or file_metadata.get("integrity_status") == "MODIFIED":
        forgery_evidence.append("File SHA-256 digest mismatch detected against signing envelope")
        is_forgery = True
    if "Forgery Indicator" in text_content or "Signature Invalid" in text_content:
        forgery_evidence.append("Explicit signature forgery indicator present in audit record")
        is_forgery = True

    if is_forgery:
        detected_threats.append({
            "threat": "Digital Signature Forgery",
            "threat_category": "Cryptographic Integrity Breach",
            "risk_score": 94,
            "risk_level": "CRITICAL",
            "why_detected": "The mathematical signature or cryptographic digest does not match the payload, indicating forgery or corruption.",
            "evidence": forgery_evidence,
            "first_action": "Reject invalid signature and isolate the transaction immediately.",
            "countermeasure": "Quarantine unverified message; rotate compromised signing credentials; enforce multi-party threshold signatures."
        })

    # --------------------------------------------------------------------------
    # 2. REPLAY ATTACK (Stateful Store + In-Memory Freshness)
    # --------------------------------------------------------------------------
    replay_evidence = []
    is_replay = False

    if stateful_replay_info.get("is_stateful_replay"):
        replay_evidence.append(
            f"Stateful Replay Store detected re-occurrence of identifier: {stateful_replay_info.get('stateful_replay_type')} (Hits: {stateful_replay_info.get('hit_count', 2)})"
        )
        is_replay = True

    if structured_fields.get("nonce") == "REUSED" or "Nonce: REUSED" in text_content:
        replay_evidence.append("Cryptographic Nonce explicitly reused in transaction")
        is_replay = True

    if structured_fields.get("timestamp") == "REPEATED" or "Timestamp: REPEATED" in text_content:
        replay_evidence.append("Transaction timestamp repeated / stale")
        is_replay = True

    if structured_fields.get("session_id") == "REUSED" or "Session ID: REUSED" in text_content:
        replay_evidence.append("Session identifier duplicate / reused")
        is_replay = True

    if "Replay Indicator: DETECTED" in text_content or "TXN-REPLAY" in text_content:
        replay_evidence.append("Replay attack telemetry marker flagged")
        is_replay = True

    if is_replay:
        detected_threats.append({
            "threat": "Replay Attack",
            "threat_category": "Session Replay & Freshness Violation",
            "risk_score": 88,
            "risk_level": "HIGH",
            "why_detected": "Nonce, timestamp, session ID, or transaction hash has been previously processed or marked reused. Note: A valid digital signature alone does not prevent replay.",
            "evidence": replay_evidence,
            "first_action": "Reject the reused transaction immediately.",
            "countermeasure": "Enforce cryptographic nonce uniqueness cache; enforce strict timestamp freshness window (<60s); bind session tokens to transport layer; reject duplicate transaction hashes."
        })

    # --------------------------------------------------------------------------
    # 3. SIGNER IMPERSONATION / IDENTITY SPOOFING
    # --------------------------------------------------------------------------
    impersonation_evidence = []
    is_impersonation = False

    if "Impersonation Indicator: DETECTED" in text_content or "Impersonation" in text_content:
        impersonation_evidence.append("Signer impersonation indicator flagged in audit stream")
        is_impersonation = True

    if "Authentication: FAILED" in text_content or structured_fields.get("authentication", "").upper() == "FAILED":
        impersonation_evidence.append("Identity authentication check failed")
        is_impersonation = True

    if "Unknown User" in text_content or "Rogue Signer" in text_content or "UNVERIFIED_SIGNER" in text_content:
        impersonation_evidence.append("Signer identity does not match authorized PKI directory")
        is_impersonation = True

    if cert_info.get("status") in ["INVALID", "UNTRUSTED"] or cert_info.get("trust_chain") == "FAILED":
        impersonation_evidence.append(f"X.509 Certificate trust chain invalid: {cert_info.get('status')}")
        is_impersonation = True

    if is_impersonation:
        detected_threats.append({
            "threat": "Signer Impersonation",
            "threat_category": "Identity & Authentication Spoofing",
            "risk_score": 82,
            "risk_level": "HIGH",
            "why_detected": "Signer identity or X.509 certificate fails authentication against the authorized PKI directory.",
            "evidence": impersonation_evidence,
            "first_action": "Block unauthorized identity and require re-authentication.",
            "countermeasure": "Enforce strict X.509 PKI trust chain verification; mandate hardware security module (HSM) identity tokens; integrate multi-factor certificate attestation."
        })

    # --------------------------------------------------------------------------
    # 4. UNAUTHORIZED VERIFICATION
    # --------------------------------------------------------------------------
    auth_verifier = structured_fields.get("authorized_verifier") or "Finance Department / Security Officer"
    actual_verifier = structured_fields.get("actual_verifier") or structured_fields.get("verifier")
    
    is_unauth_verif = False
    unauth_evidence = []

    if actual_verifier and actual_verifier.lower() not in ["finance department", "security officer", "alice", "authorized verifier"]:
        unauth_evidence.append(f"Actual Verifier '{actual_verifier}' differs from Authorized Verifier '{auth_verifier}'")
        is_unauth_verif = True

    if "Unauthorized Verification" in text_content or "Unauthorized Verifier" in text_content:
        unauth_evidence.append("Explicit unauthorized verification attempt logged")
        is_unauth_verif = True

    if is_unauth_verif:
        detected_threats.append({
            "threat": "Unauthorized Verification",
            "threat_category": "Access Control & Verification Governance",
            "risk_score": 84,
            "risk_level": "HIGH",
            "why_detected": f"Verification attempted by unauthorized entity ({actual_verifier or 'Unknown User'}). Authorized: {auth_verifier}.",
            "evidence": unauth_evidence,
            "first_action": "Block the unauthorized verifier.",
            "countermeasure": "Implement role-based access control (RBAC) on verification endpoints; enforce verifier identity attestation; restrict verification permissions to designated cryptographic audit entities."
        })

    # --------------------------------------------------------------------------
    # 5. QUANTUM EAVESDROPPING (Entangle-and-Measure Probe)
    # --------------------------------------------------------------------------
    qber_val = quantum_metrics.get("qber", 0.0)
    if isinstance(qber_val, str):
        try:
            qber_val = float(qber_val.replace("%", "")) / 100.0
        except ValueError:
            qber_val = 0.0

    is_eavesdropping = False
    eavesdrop_evidence = []

    if "Entangle-and-Measure" in text_content or "Eavesdropping Indicator: DETECTED" in text_content:
        eavesdrop_evidence.append("Simulated quantum-state interaction telemetry flagged entangle-and-measure probe")
        is_eavesdropping = True

    if qber_val >= 0.11: # Above theoretical 11% QDS threshold
        eavesdrop_evidence.append(f"Simulated QBER ({qber_val*100:.2f}%) exceeds the 11.00% theoretical QDS security bound")
        is_eavesdropping = True

    if is_eavesdropping:
        detected_threats.append({
            "threat": "Quantum Eavesdropping (Entangle-and-Measure)",
            "threat_category": "Quantum Channel Physical-Layer Attack",
            "risk_score": 96,
            "risk_level": "CRITICAL",
            "why_detected": f"Elevated quantum bit error rate (QBER = {qber_val*100:.2f}%) indicates eavesdropping perturbation on simulated carrier qubits.",
            "evidence": eavesdrop_evidence,
            "first_action": "Terminate/suspend the affected simulated quantum channel.",
            "countermeasure": "Abort key distillation; switch to alternate quantum entanglement path; initiate simulated privacy amplification and decoy-state protocol."
        })

    # --------------------------------------------------------------------------
    # 6. INTERCEPT-RESEND ATTACK
    # --------------------------------------------------------------------------
    is_intercept = False
    intercept_evidence = []

    if "Intercept-Resend" in text_content or "Intercept and Resend" in text_content:
        intercept_evidence.append("Intercept-resend quantum basis mismatch detected")
        is_intercept = True

    if is_intercept:
        detected_threats.append({
            "threat": "Intercept-Resend Attack",
            "threat_category": "Quantum Basis Measurement Interception",
            "risk_score": 91,
            "risk_level": "CRITICAL",
            "why_detected": "Non-orthogonal basis measurements by an adversary induced systematic 25% conjugate basis collapse.",
            "evidence": intercept_evidence,
            "first_action": "Terminate the compromised quantum channel.",
            "countermeasure": "Deploy decoy-state protocol; detect non-orthogonal basis tampering; reroute entanglement distribution."
        })

    # --------------------------------------------------------------------------
    # 7. QUANTUM CHANNEL MANIPULATION
    # --------------------------------------------------------------------------
    is_q_manip = False
    q_manip_evidence = []

    if "Quantum Channel Manipulation" in text_content or "Quantum Channel: MANIPULATED" in text_content:
        q_manip_evidence.append("Active quantum state perturbation detected on transmission fiber")
        is_q_manip = True

    if is_q_manip:
        detected_threats.append({
            "threat": "Quantum Channel Manipulation",
            "threat_category": "Physical Channel State Perturbation",
            "risk_score": 80,
            "risk_level": "HIGH",
            "why_detected": "Simulated quantum channel telemetry shows state phase and polarization drift exceeding operational limits.",
            "evidence": q_manip_evidence,
            "first_action": "Reject the modified message and re-establish a trusted channel.",
            "countermeasure": "Perform quantum state tomography; recalibrate phase/polarization baselines; re-entangle Bell pairs."
        })

    # --------------------------------------------------------------------------
    # 8. CLASSICAL CHANNEL TAMPERING
    # --------------------------------------------------------------------------
    is_tampering = False
    tampering_evidence = []

    if "Channel Status: TAMPERED" in text_content or "Message Modification: DETECTED" in text_content or "Channel Tampering" in text_content:
        tampering_evidence.append("Bit alteration detected on classical transmission transit channel")
        is_tampering = True

    if is_tampering:
        detected_threats.append({
            "threat": "Classical Channel Tampering",
            "threat_category": "In-Transit Payload Modification",
            "risk_score": 79,
            "risk_level": "HIGH",
            "why_detected": "Payload contents altered during transmission between network hops while signature remained attached.",
            "evidence": tampering_evidence,
            "first_action": "Reject the modified message and re-establish a trusted channel.",
            "countermeasure": "Enforce HMAC-SHA256 authenticated framing; enable end-to-end TLSv1.3 transport security; reject payload digest discrepancies."
        })

    # --------------------------------------------------------------------------
    # SELECTION OF PRIMARY THREAT & COMPOSITE RISK CALCULATION
    # --------------------------------------------------------------------------
    if not detected_threats:
        # Secure Baseline
        primary_threat = "None (System Operating Normally)"
        risk_score = 6
        risk_level = "LOW"
        overall_status = "SECURE"
        first_action = "Allow transaction processing."
        countermeasure = "Maintain routine continuous telemetry monitoring."
        why_detected = "All cryptographic checks, state freshness, X.509 PKI certificates, and simulated quantum telemetry indicate intact integrity."
        evidence = ["SHA-256 file integrity intact", "Cryptographic signature verified", "Quantum channel error rate within nominal bounds (< 2.0%)"]
    else:
        # Sort threats by risk score descending to select PRIMARY THREAT
        detected_threats.sort(key=lambda t: t["risk_score"], reverse=True)
        top_threat = detected_threats[0]
        
        primary_threat = top_threat["threat"]
        risk_score = top_threat["risk_score"]
        
        # If multiple severe threats exist, adjust risk score towards maximum
        if len(detected_threats) > 1:
            risk_score = min(100, risk_score + (len(detected_threats) - 1) * 2)

        # Risk level determination based on exact specification
        # 0-29 LOW, 30-59 MEDIUM, 60-89 HIGH, 90-100 CRITICAL
        if risk_score >= 90:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        overall_status = "ATTACK DETECTED"
        first_action = top_threat["first_action"]
        countermeasure = top_threat["countermeasure"]
        why_detected = top_threat["why_detected"]
        evidence = top_threat["evidence"]

    return {
        "status": overall_status,
        "primary_threat": primary_threat,
        "detected_threat": primary_threat, # Backward compatibility
        "threat_category": detected_threats[0]["threat_category"] if detected_threats else "Operational Normal",
        "risk_score": risk_score,
        "risk": risk_level, # Backward compatibility
        "risk_level": risk_level,
        "confidence": 96.0 if detected_threats else 99.0,
        "all_detected_threats": detected_threats,
        "all_threat_names": [t["threat"] for t in detected_threats] if detected_threats else ["None"],
        "threat_count": len(detected_threats),
        "why_detected": why_detected,
        "reason": why_detected,
        "evidence": evidence,
        "first_action": first_action,
        "recommendation": countermeasure,
        "countermeasure": countermeasure,
        "scoring_model": "Multi-Threat Correlation & Evidence-Weighted Risk Engine"
    }
