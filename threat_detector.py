"""
Quantum Digital Signature Security Analyzer
Threat Detector Module: Comprehensive Multi-Threat Correlation & Evidence-Weighted Risk Engine
Evaluates: Normal, Forgery, Replay, Impersonation, Intercept-Resend, Entangle-and-Measure,
Classical Channel Tampering, and Certificate / Trust Failure.
"""

import re
import math
from typing import Dict, Any, List, Optional

def parse_quantum_values(text: str) -> Dict[str, Any]:
    """Extracts numerical QBER, Mismatch Rate, Rounds, Matches, and Mismatches if present in telemetry."""
    metrics = {}
    
    qber_match = re.search(r'QBER\s*[:=]\s*([0-9]*\.?[0-9]+)', text, re.IGNORECASE)
    if qber_match:
        try:
            metrics['qber'] = float(qber_match.group(1))
        except ValueError:
            pass

    mismatch_rate_match = re.search(r'Mismatch\s*Rate\s*[:=]\s*([0-9]*\.?[0-9]+)', text, re.IGNORECASE)
    if mismatch_rate_match:
        try:
            metrics['mismatch_rate'] = float(mismatch_rate_match.group(1))
        except ValueError:
            pass

    rounds_match = re.search(r'Rounds\s*[:=]\s*([0-9]+)', text, re.IGNORECASE)
    if rounds_match:
        try:
            metrics['rounds'] = int(rounds_match.group(1))
        except ValueError:
            pass

    matches_match = re.search(r'Matches\s*[:=]\s*([0-9]+)', text, re.IGNORECASE)
    if matches_match:
        try:
            metrics['matches'] = int(matches_match.group(1))
        except ValueError:
            pass

    mismatches_match = re.search(r'Mismatches\s*[:=]\s*([0-9]+)', text, re.IGNORECASE)
    if mismatches_match:
        try:
            metrics['mismatches'] = int(mismatches_match.group(1))
        except ValueError:
            pass

    return metrics

def analyze_signature_indicators(text: str) -> Dict[str, Any]:
    """
    Extracts digital signature heuristic indicators.
    Clearly distinguishes 'Signature Indicator Detected' from 'Cryptographically Verified'.
    """
    sig_present = False
    sig_status = "NOT DETECTED"
    sig_algo = "N/A"
    signer_info = "Unknown / Not specified"
    verification_result = "UNVERIFIED"
    indicators_found = []

    algos = [
        "ML-DSA-65", "ML-DSA", "SLH-DSA", "LMS", "XMSS", "Dilithium", "Falcon", "SPHINCS+",
        "ECDSA-P256-SHA256", "ECDSA-P384", "ECDSA", "Ed25519", "Ed448",
        "RSA-4096", "RSA-3072", "RSA-2048", "RSA-1024", "RSA", "PAdES", "CAdES", "PKCS#7", "X.509"
    ]
    for a in algos:
        if re.search(rf'\b{re.escape(a)}\b', text, re.IGNORECASE):
            sig_algo = a
            sig_present = True
            indicators_found.append(f"Algorithm indicator: {a}")
            break

    signer_match = re.search(r'(?:Signed By|Signer|Signer Identity|Issuer)\s*[:=]\s*([^\r\n,]+)', text, re.IGNORECASE)
    if signer_match:
        signer_info = signer_match.group(1).strip()
        sig_present = True
        indicators_found.append(f"Signer identity: {signer_info}")

    if re.search(r'(?:Digital Signature|Signature Status|Signature|Certificate|X509|PKCS|CMS|PAdES|CAdES)', text, re.IGNORECASE):
        sig_present = True

    if re.search(r'Signature Status\s*[:=]\s*INVALID|Invalid Signature|Signature Invalid', text, re.IGNORECASE):
        sig_status = "INVALID (Heuristic Indicator Flagged)"
        verification_result = "FAILED_HEURISTIC_CHECK"
        indicators_found.append("Signature explicitly marked INVALID in content stream")
    elif re.search(r'Signature Status\s*[:=]\s*VALID|Valid Signature', text, re.IGNORECASE):
        sig_status = "VALID (Indicator present - Heuristic)"
        verification_result = "INDICATOR_PRESENT_NOT_CRYPTOGRAPHICALLY_PROVEN"
        indicators_found.append("Signature format valid indicator detected")
    elif sig_present:
        sig_status = "PRESENT (Heuristic format detected)"
        verification_result = "HEURISTIC_PRESENT"

    hash_mismatch = bool(re.search(r'Hash Mismatch\s*[:=]\s*TRUE|Digest Mismatch|Integrity Violation', text, re.IGNORECASE))
    if hash_mismatch:
        indicators_found.append("Hash digest mismatch indicator flagged in payload")

    return {
        "signature_present": sig_present,
        "signature_status": sig_status,
        "signature_algorithm": sig_algo if sig_algo != "N/A" else ("Standard Digital Signature" if sig_present else "None Detected"),
        "signer_information": signer_info,
        "verification_result": verification_result,
        "hash_mismatch": hash_mismatch,
        "indicators": indicators_found,
        "note": "Signature indicator detected via prototype parser. Formal mathematical verification requires public key PKI chain validation."
    }

def detect_threats_automatic(
    text: str,
    structured_fields: Optional[Dict[str, str]] = None,
    stateful_replay_info: Optional[Dict[str, Any]] = None,
    crypto_verification_info: Optional[Dict[str, Any]] = None,
    cert_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Performs comprehensive multi-threat correlation across all 8 threat vectors.
    Uses an Evidence-Weighted Risk Model to assign calibrated scores and select primary/additional threats.
    """
    if structured_fields is None:
        structured_fields = {}
    
    detected_threat_list = []
    
    # -------------------------------------------------------------
    # 1. REPLAY ATTACK DETECTION (Heuristic + Stateful)
    # -------------------------------------------------------------
    replay_evidence = []
    replay_weight = 0
    
    # Check text indicators
    if re.search(r'Replay Indicator\s*[:=]\s*DETECTED|Replay Detected', text, re.IGNORECASE):
        replay_evidence.append("Replay indicator flag detected in payload stream")
        replay_weight += 35
    if re.search(r'Nonce\s*[:=]\s*REUSED|Reused Nonce', text, re.IGNORECASE) or structured_fields.get("nonce") == "REUSED":
        replay_evidence.append("Nonce value flagged as REUSED")
        replay_weight += 30
    if re.search(r'Timestamp\s*[:=]\s*REPEATED|Repeated Timestamp|Timestamp Stale', text, re.IGNORECASE) or structured_fields.get("timestamp") == "REPEATED":
        replay_evidence.append("Timestamp repeated or stale outside freshness window")
        replay_weight += 15
    if re.search(r'Session ID\s*[:=]\s*REUSED|Reused Session ID', text, re.IGNORECASE) or structured_fields.get("session_id") == "REUSED":
        replay_evidence.append("Session identifier duplicate / reused")
        replay_weight += 15
    if re.search(r'Previous Transaction\s*[:=]|TXN-REPLAY', text, re.IGNORECASE):
        replay_evidence.append("Prior transaction reference pattern matched in payload")
        replay_weight += 20
        
    # Check Stateful Replay Store
    if stateful_replay_info and stateful_replay_info.get("is_stateful_replay"):
        hits = stateful_replay_info.get("hit_count", 2)
        replay_evidence.append(f"Stateful Replay Store Match: Identifier observed {hits} times (First seen: {stateful_replay_info.get('first_seen', 'previously')})")
        replay_weight += 45

    if replay_evidence:
        raw_score = min(100, max(70, replay_weight))
        calc_score = 90 if raw_score >= 85 else raw_score
        risk_level = "CRITICAL" if calc_score >= 90 else "HIGH"
        detected_threat_list.append({
            "threat": "Replay Attack",
            "threat_category": "Authentication / Message Replay",
            "risk": risk_level,
            "risk_score": calc_score,
            "confidence": 95,
            "reason": "A previously accepted message, nonce, timestamp, or session identifier has been re-submitted.",
            "evidence": replay_evidence,
            "first_action": "Reject the reused transaction or nonce immediately.",
            "recommendation": "Generate a cryptographically random unique nonce for every transaction, enforce strict timestamp freshness validation (+/-120s), bind signatures to a unique session token, and maintain a persistent stateful replay cache.",
            "intensity": calc_score
        })

    # -------------------------------------------------------------
    # 2. FORGERY DETECTION (Cryptographic & Heuristic)
    # -------------------------------------------------------------
    forgery_evidence = []
    forgery_weight = 0
    
    if crypto_verification_info and crypto_verification_info.get("mathematical_verification") == "FAILED":
        forgery_evidence.append("Mathematical cryptographic signature verification FAILED against public key digest")
        forgery_weight += 50
    if re.search(r'Forgery Indicator\s*[:=]\s*DETECTED|Forgery Detected', text, re.IGNORECASE):
        forgery_evidence.append("Forgery indicator flagged in telemetry")
        forgery_weight += 35
    if re.search(r'Signature Status\s*[:=]\s*INVALID|Invalid Signature|Signature Invalid', text, re.IGNORECASE):
        forgery_evidence.append("Signature status explicitly marked INVALID")
        forgery_weight += 35
    if re.search(r'Hash Mismatch\s*[:=]\s*TRUE|Digest Mismatch', text, re.IGNORECASE):
        forgery_evidence.append("Signed hash digest mismatch with calculated message payload")
        forgery_weight += 30

    if forgery_evidence:
        calc_score = min(100, max(85, forgery_weight))
        detected_threat_list.append({
            "threat": "Forgery",
            "threat_category": "Cryptographic Integrity / Signature Forgery",
            "risk": "CRITICAL" if calc_score >= 90 else "HIGH",
            "risk_score": calc_score,
            "confidence": 94,
            "reason": "Cryptographic signature validation failed or an explicit forgery indicator was detected.",
            "evidence": forgery_evidence,
            "first_action": "Reject the invalid signature and do not trust the transaction.",
            "recommendation": "Verify signature mathematically, validate signer certificate, validate public key, check certificate chain, and compare signed digest with calculated digest.",
            "intensity": calc_score
        })

    # -------------------------------------------------------------
    # 3. IMPERSONATION DETECTION
    # -------------------------------------------------------------
    impersonation_evidence = []
    imp_weight = 0
    if re.search(r'Impersonation Indicator\s*[:=]\s*DETECTED|Impersonation Detected', text, re.IGNORECASE):
        impersonation_evidence.append("Impersonation indicator flagged in session log")
        imp_weight += 40
    if re.search(r'Unknown User|Unauthorized User|Rogue Entity|Rogue Signer', text, re.IGNORECASE):
        impersonation_evidence.append("Signer identity is unrecognized or absent from authorized directory")
        imp_weight += 30
    if re.search(r'Authentication\s*[:=]\s*FAILED|Authentication Failed', text, re.IGNORECASE):
        impersonation_evidence.append("Signer authentication challenge failed")
        imp_weight += 30
    if cert_info and cert_info.get("status") == "UNTRUSTED":
        impersonation_evidence.append("Untrusted or self-signed certificate identity mismatch")
        imp_weight += 25

    if impersonation_evidence:
        calc_score = min(100, max(75, imp_weight))
        detected_threat_list.append({
            "threat": "Impersonation",
            "threat_category": "Identity Spoofing / Unauthorized Signer",
            "risk": "HIGH",
            "risk_score": calc_score,
            "confidence": 92,
            "reason": "Signer credentials could not be authenticated against trusted identity certificates.",
            "evidence": impersonation_evidence,
            "first_action": "Block the suspicious identity/session immediately.",
            "recommendation": "Verify identity, validate certificate, validate authorization, use strong authentication, and terminate suspicious sessions.",
            "intensity": calc_score
        })

    # -------------------------------------------------------------
    # 4. CLASSICAL CHANNEL TAMPERING
    # -------------------------------------------------------------
    tampering_evidence = []
    tamp_weight = 0
    if re.search(r'Channel Status\s*[:=]\s*TAMPERED|Channel Tampered|Channel Tampering', text, re.IGNORECASE):
        tampering_evidence.append("Communication channel flagged as TAMPERED")
        tamp_weight += 40
    if re.search(r'Modification Detected|Message Modification\s*[:=]\s*DETECTED|Payload Altered', text, re.IGNORECASE):
        tampering_evidence.append("In-transit message body alteration detected")
        tamp_weight += 35
    if re.search(r'Integrity Check\s*[:=]\s*FAILED', text, re.IGNORECASE):
        tampering_evidence.append("Payload integrity checksum verification failed")
        tamp_weight += 30

    if tampering_evidence:
        calc_score = min(100, max(75, tamp_weight))
        detected_threat_list.append({
            "threat": "Classical Channel Tampering",
            "threat_category": "Data Transmission Integrity",
            "risk": "HIGH",
            "risk_score": calc_score,
            "confidence": 90,
            "reason": "Data in transit appears to have been altered or intercepted along the classical communication channel.",
            "evidence": tampering_evidence,
            "first_action": "Reject the modified message immediately.",
            "recommendation": "Use authenticated communication channels (AEAD / TLS 1.3), apply signed manifests, verify SHA-256 digests against reference digests, and reject integrity failures.",
            "intensity": calc_score
        })

    # -------------------------------------------------------------
    # 5. INTERCEPT-RESEND DETECTION
    # -------------------------------------------------------------
    intercept_evidence = []
    int_weight = 0
    if re.search(r'Intercept-Resend|Intercept Resend', text, re.IGNORECASE):
        intercept_evidence.append("Intercept-Resend signature transmission anomaly detected")
        int_weight += 40
    if re.search(r'Message Intercepted|Message Replaced|Transmission Modified', text, re.IGNORECASE):
        intercept_evidence.append("Transmission stream replaced or injected by intermediary proxy")
        int_weight += 35
    if re.search(r'Unexpected Message|Sequence Out of Order', text, re.IGNORECASE):
        intercept_evidence.append("Asynchronous unexpected packet structure received")
        int_weight += 25

    if intercept_evidence:
        calc_score = min(100, max(80, int_weight))
        detected_threat_list.append({
            "threat": "Intercept-Resend",
            "threat_category": "Active MITM / Intercept-Resend",
            "risk": "HIGH",
            "risk_score": calc_score,
            "confidence": 93,
            "reason": "An active intermediary is intercepting, altering, or re-transmitting signature packets.",
            "evidence": intercept_evidence,
            "first_action": "Reject the unexpected or modified message.",
            "recommendation": "Authenticate the communication channel, verify message integrity, use session binding, compare expected and received metadata, and monitor quantum-inspired QBER metrics where simulated.",
            "intensity": calc_score
        })

    # -------------------------------------------------------------
    # 6. QUANTUM EAVESDROPPING / ENTANGLE-AND-MEASURE
    # -------------------------------------------------------------
    quantum_evidence = []
    q_metrics = parse_quantum_values(text)
    q_weight = 0
    
    if re.search(r'Entangle-and-Measure Indicator\s*[:=]\s*DETECTED|Entangle-and-Measure', text, re.IGNORECASE):
        quantum_evidence.append("Simulated Entangle-and-Measure quantum disturbance indicator detected")
        q_weight += 45
    if re.search(r'Eavesdropping Indicator\s*[:=]\s*DETECTED|Quantum Eavesdropping|Eavesdropping Detected', text, re.IGNORECASE):
        quantum_evidence.append("Quantum channel eavesdropping threshold breached")
        q_weight += 40
    if q_metrics.get('qber', 0) > 0.11:
        quantum_evidence.append(f"Elevated QBER detected: {q_metrics['qber']:.4f} (Theoretical Threshold: 0.1100)")
        q_weight += 35
    if q_metrics.get('mismatch_rate', 0) > 0.15:
        quantum_evidence.append(f"Quantum state mismatch rate: {q_metrics['mismatch_rate']:.4f}")
        q_weight += 20

    if quantum_evidence:
        calc_score = min(100, max(95, q_weight))
        detected_threat_list.append({
            "threat": "Entangle-and-Measure",
            "threat_category": "Quantum Eavesdropping (Simulated)",
            "risk": "CRITICAL",
            "risk_score": calc_score,
            "confidence": 98,
            "reason": "Simulated quantum-state interaction caused an elevated Quantum Bit Error Rate (QBER), consistent with possible quantum channel disturbance.",
            "evidence": quantum_evidence,
            "first_action": "Abort the affected quantum communication session immediately.",
            "recommendation": "Abort affected session, discard compromised key material, re-establish secure quantum-inspired key exchange, and perform security verification before continuing.",
            "intensity": calc_score,
            "is_quantum": True
        })

    # -------------------------------------------------------------
    # 7. CERTIFICATE / TRUST FAILURE
    # -------------------------------------------------------------
    cert_threat_evidence = []
    cert_weight = 0
    if cert_info:
        if cert_info.get("status") == "INVALID" or "EXPIRED" in cert_info.get("validity_status", ""):
            cert_threat_evidence.append("Signer X.509 certificate is EXPIRED or mathematically invalid")
            cert_weight += 40
        if cert_info.get("is_self_signed"):
            cert_threat_evidence.append("Self-signed certificate untrusted by PKI trust anchor")
            cert_weight += 30
        if cert_info.get("is_weak_key"):
            cert_threat_evidence.append("Weak cryptographic key length (< 2048-bit RSA) or obsolete hash algorithm")
            cert_weight += 25
        if cert_info.get("revocation", {}).get("status") == "REVOKED":
            cert_threat_evidence.append("Certificate is listed as REVOKED in OCSP/CRL responder")
            cert_weight += 50

    if cert_threat_evidence:
        calc_score = min(100, max(75, cert_weight))
        detected_threat_list.append({
            "threat": "Certificate / Trust Failure",
            "threat_category": "PKI & Certificate Validation",
            "risk": "HIGH",
            "risk_score": calc_score,
            "confidence": 91,
            "reason": "Signer certificate validation failed due to expiration, untrusted chain, or weak cryptographic parameters.",
            "evidence": cert_threat_evidence,
            "first_action": "Reject the certificate and untrusted digital signature.",
            "recommendation": "Renew expired certificates, validate against trusted root CA trust store, check OCSP/CRL revocation, and mandate minimum RSA-2048 or PQC ML-DSA keys.",
            "intensity": calc_score
        })

    # -------------------------------------------------------------
    # 8. RESOLVE PRIMARY THREAT OR NORMAL
    # -------------------------------------------------------------
    if not detected_threat_list:
        return {
            "status": "SECURE",
            "detected_threat": "None",
            "threat_category": "Normal / Trusted Operation",
            "risk": "LOW",
            "risk_score": 5,
            "confidence": 96,
            "reason": "No tampering, replay, forgery, certificate failure, or quantum channel disturbance indicators detected.",
            "evidence": ["All cryptographic, PKI, and transmission indicators appear clean."],
            "first_action": "Continue normal security verification.",
            "recommendation": "Continue monitoring and retain the security audit record.",
            "intensity": 5,
            "additional_threats": [],
            "all_detected_threats": [],
            "scoring_model": "Evidence-Weighted Risk Model"
        }

    # Sort by risk score descending
    detected_threat_list.sort(key=lambda x: x["risk_score"], reverse=True)
    primary = detected_threat_list[0]
    additional = [t["threat"] for t in detected_threat_list[1:]]

    return {
        "status": "ATTACK DETECTED",
        "detected_threat": primary["threat"],
        "threat_category": primary["threat_category"],
        "risk": primary["risk"],
        "risk_score": primary["risk_score"],
        "confidence": primary["confidence"],
        "reason": primary["reason"],
        "evidence": primary["evidence"],
        "first_action": primary["first_action"],
        "recommendation": primary["recommendation"],
        "intensity": primary["intensity"],
        "additional_threats": additional,
        "all_detected_threats": detected_threat_list,
        "scoring_model": "Evidence-Weighted Risk Model"
    }

def generate_attack_scenario_table(
    primary_threat_name: str,
    status: str,
    simulation_mode: str = "Automatic Detection"
) -> List[Dict[str, Any]]:
    """
    Builds the complete 8-row Attack Scenario Analysis Matrix.
    Rows:
      1. Normal
      2. Forgery
      3. Replay
      4. Impersonation
      5. Intercept-Resend
      6. Entangle-and-Measure
      7. Classical Channel Tampering
      8. Certificate / Trust Failure
    """
    scenarios = [
        {
            "attack": "Normal",
            "description": "Baseline valid signature and channel operation",
            "default_risk": "LOW",
            "default_score": 5,
            "default_reason": "No malicious indicators detected in file stream."
        },
        {
            "attack": "Forgery",
            "description": "Mathematical signature alteration or invalid public key",
            "default_risk": "HIGH / CRITICAL",
            "default_score": 92,
            "default_reason": "Invalid cryptographic signature or broken integrity tag."
        },
        {
            "attack": "Replay",
            "description": "Reuse of previously valid nonce, session, or timestamp",
            "default_risk": "HIGH",
            "default_score": 85,
            "default_reason": "Reused nonce, duplicate session identifier, or stateful replay match."
        },
        {
            "attack": "Impersonation",
            "description": "Signer certificate spoofing or unauthorized identity claim",
            "default_risk": "HIGH",
            "default_score": 88,
            "default_reason": "Unauthenticated user or rogue issuer identity."
        },
        {
            "attack": "Intercept-Resend",
            "description": "Active eavesdropper intercepting and re-transmitting payload",
            "default_risk": "HIGH",
            "default_score": 90,
            "default_reason": "In-flight message intercepted and substituted."
        },
        {
            "attack": "Entangle-and-Measure",
            "description": "Quantum state disturbance & high QBER eavesdropping",
            "default_risk": "CRITICAL",
            "default_score": 98,
            "default_reason": "Simulated quantum channel disturbance / elevated QBER detected."
        },
        {
            "attack": "Classical Channel Tampering",
            "description": "In-transit modification of classical communication channel",
            "default_risk": "HIGH",
            "default_score": 85,
            "default_reason": "Message body alteration or communication channel tampered."
        },
        {
            "attack": "Certificate / Trust Failure",
            "description": "Expired, untrusted root, or revoked X.509 certificate",
            "default_risk": "HIGH",
            "default_score": 85,
            "default_reason": "Certificate expired, self-signed, or failed trust chain verification."
        }
    ]

    table = []
    for sc in scenarios:
        row_attack = sc["attack"]
        is_match = False

        if row_attack == "Normal" and (primary_threat_name in ["None", "Normal"] or status == "SECURE"):
            is_match = True
        elif row_attack == "Replay" and "Replay" in primary_threat_name:
            is_match = True
        elif row_attack == "Forgery" and "Forgery" in primary_threat_name:
            is_match = True
        elif row_attack == "Impersonation" and "Impersonation" in primary_threat_name:
            is_match = True
        elif row_attack == "Intercept-Resend" and "Intercept-Resend" in primary_threat_name:
            is_match = True
        elif row_attack == "Entangle-and-Measure" and ("Entangle" in primary_threat_name or "Quantum" in primary_threat_name):
            is_match = True
        elif row_attack == "Classical Channel Tampering" and ("Tampering" in primary_threat_name or "Channel" in primary_threat_name):
            is_match = True
        elif row_attack == "Certificate / Trust Failure" and ("Certificate" in primary_threat_name or "Trust" in primary_threat_name):
            is_match = True

        if is_match:
            if simulation_mode != "Automatic Detection" and simulation_mode != "None":
                row_status = "SIMULATION"
            else:
                row_status = "AUTO-DETECTED"
            risk = "LOW" if row_attack == "Normal" else ("CRITICAL" if sc["default_score"] >= 95 else "HIGH")
            score = sc["default_score"]
            reason = f"Active indicator matches: {sc['default_reason']}"
        else:
            row_status = "NOT DETECTED"
            risk = "LOW"
            score = 0
            reason = "No active indicator found for this threat vector in current file."

        table.append({
            "attack": row_attack,
            "status": row_status,
            "risk": risk,
            "risk_score": score,
            "reason": reason
        })

    return table
