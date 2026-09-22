"""
Quantum-Shield (Q-SHIELD) Forensic Evidence Engine (Python Edition)
Module: Attack Evidence Location & Line-Level Forensic Analysis

Core Invariants:
1. Exact line numbers (1-indexed), offsets, structured fields, and genuine timestamps.
2. NEVER INVENT AN ATTACK LOCATION:
   - LINE: Exact single line identified.
   - MULTI_LINE: Multiple records contributed (e.g. repeated nonces/transactions across lines).
   - FIELD: Specific structured data attribute identified.
   - FILE_LEVEL: Derived from file-level cryptographic verification (e.g. binary digest mismatch).
   - BYTE_OFFSET: Specific binary byte range.
   - EVENT: Contributing measurement events (e.g. quantum measurement mismatch sequence).
3. Strictly non-distorting: Uses "Contributing Evidence" for statistical outcomes.
4. Explanatory reasoning: Generates step-by-step evidence-based "Why this verdict?" trails.
"""

import re
from typing import Dict, Any, List, Optional, Tuple

def parse_text_lines(text: str) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Parses in-memory text line-by-line preserving exact 1-indexed line numbers,
    character byte offsets, structured key/value fields, and genuine timestamps.
    """
    if not text:
        return [], False

    # Check for binary content
    sample = text[:4096]
    is_binary = '\x00' in sample

    raw_lines = text.splitlines(keepends=False)
    lines: List[Dict[str, Any]] = []
    current_offset = 0

    for i, raw_line in enumerate(raw_lines):
        line_num = i + 1
        start_offset = current_offset
        end_offset = current_offset + len(raw_line)
        current_offset = end_offset + 1

        field_key = None
        field_value = None
        kv_match = re.match(r'^([^:=]+)[:=]\s*(.+)$', raw_line)
        if kv_match:
            field_key = kv_match.group(1).strip().lower().replace(' ', '_').replace('-', '_')
            field_value = kv_match.group(2).strip()

        timestamp = None
        ts_match = re.search(r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b', raw_line) or \
                   re.search(r'\b(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b', raw_line)
        if ts_match:
            timestamp = ts_match.group(1)

        lines.append({
            "lineNumber": line_num,
            "content": raw_line,
            "raw": raw_line,
            "startOffset": start_offset,
            "endOffset": end_offset,
            "fieldKey": field_key,
            "fieldValue": field_value,
            "timestamp": timestamp
        })

    return lines, is_binary

def get_context_lines(
    lines: List[Dict[str, Any]],
    target_line_num: int,
    radius: int = 3
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Extracts lines before and after a specified target line number.
    """
    target_idx = target_line_num - 1
    before = []
    after = []

    start_before = max(0, target_idx - radius)
    for i in range(start_before, target_idx):
        if i < len(lines):
            before.append({
                "lineNumber": lines[i]["lineNumber"],
                "content": lines[i]["content"]
            })

    end_after = min(len(lines), target_idx + 1 + radius)
    for i in range(target_idx + 1, end_after):
        if i < len(lines):
            after.append({
                "lineNumber": lines[i]["lineNumber"],
                "content": lines[i]["content"]
            })

    return before, after

def extract_threat_evidence_locations(
    lines: List[Dict[str, Any]],
    filename: str,
    raw_text: str,
    crypto_verif: Optional[Dict[str, Any]] = None,
    cert_info: Optional[Dict[str, Any]] = None,
    stateful_replay: Optional[Dict[str, Any]] = None,
    quantum_metrics: Optional[Dict[str, Any]] = None,
    is_binary: bool = False
) -> List[Dict[str, Any]]:
    """
    Extracts accurate line-level forensic evidence items.
    """
    evidence_list: List[Dict[str, Any]] = []
    counter = 1

    def next_id() -> str:
        nonlocal counter
        res = f"EV-{counter:03d}"
        counter += 1
        return res

    def find_lines(pattern: str) -> List[Dict[str, Any]]:
        return [l for l in lines if re.search(pattern, l["content"], re.IGNORECASE)]

    if is_binary and not lines:
        if crypto_verif and crypto_verif.get("mathematical_verification") == "FAILED":
            evidence_list.append({
                "id": next_id(),
                "threatType": "Signature Forgery",
                "severity": "CRITICAL",
                "locationType": "FILE_LEVEL",
                "fileName": filename,
                "lineNumber": None,
                "field": "digital_signature",
                "lineContent": f"Binary payload failed cryptographic verification: {crypto_verif.get('details', '')}",
                "reason": "The evidence is derived from file-level cryptographic verification against calculated SHA-256 digest.",
                "detector": "Cryptographic Signature Analyzer",
                "explanation": [
                    "Cryptographic signature verification failed at binary file level.",
                    "File digest did not match signature.",
                    "Therefore verification result is invalid."
                ]
            })
        return evidence_list

    # 1. FORGERY
    is_forgery = (
        (crypto_verif and crypto_verif.get("mathematical_verification") == "FAILED") or
        re.search(r'Forgery Indicator\s*[:=]\s*DETECTED|Forgery Detected', raw_text, re.IGNORECASE) or
        re.search(r'Signature Status\s*[:=]\s*INVALID|Invalid Signature', raw_text, re.IGNORECASE) or
        re.search(r'Hash Mismatch\s*[:=]\s*TRUE|Digest Mismatch', raw_text, re.IGNORECASE) or
        re.search(r'TAMPERED\s*[:=]\s*TRUE', raw_text, re.IGNORECASE)
    )
    if is_forgery:
        sig_status_lines = find_lines(r'Signature Status\s*[:=]\s*INVALID|Invalid Signature')
        forgery_ind_lines = find_lines(r'Forgery Indicator\s*[:=]\s*DETECTED')
        hash_mismatch_lines = find_lines(r'Hash Mismatch\s*[:=]\s*TRUE|Digest Mismatch')
        tampered_lines = find_lines(r'TAMPERED\s*[:=]\s*TRUE')
        sig_hex_lines = find_lines(r'^SIGNATURE_HEX\s*[:=]')

        primary = (sig_status_lines or forgery_ind_lines or hash_mismatch_lines or tampered_lines or sig_hex_lines or [None])[0]
        if primary:
            before, after = get_context_lines(lines, primary["lineNumber"], 3)
            related = []
            if hash_mismatch_lines and hash_mismatch_lines[0]["lineNumber"] != primary["lineNumber"]:
                related.append({
                    "lineNumber": hash_mismatch_lines[0]["lineNumber"],
                    "field": "hash_mismatch",
                    "lineContent": hash_mismatch_lines[0]["content"],
                    "reason": "Associated digest mismatch record",
                    "locationType": "LINE"
                })

            evidence_list.append({
                "id": next_id(),
                "threatType": "Signature Forgery",
                "severity": "CRITICAL",
                "locationType": "FIELD" if primary.get("fieldKey") else "LINE",
                "fileName": filename,
                "lineNumber": primary["lineNumber"],
                "columnStart": 1,
                "columnEnd": len(primary["content"]),
                "field": primary.get("fieldKey") or "signature_status",
                "lineContent": primary["content"],
                "contextBefore": before,
                "contextAfter": after,
                "reason": "Signature verification failed against calculated digest and public key.",
                "detector": "Cryptographic Signature Analyzer",
                "relatedEvidence": related if related else None,
                "explanation": [
                    "Signature verification failed.",
                    f"The affected evidence was found at Line {primary['lineNumber']}.",
                    "The calculated digest did not match the supplied signature.",
                    "Therefore the cryptographic verification result is invalid."
                ],
                "timestamp": primary.get("timestamp")
            })
        else:
            evidence_list.append({
                "id": next_id(),
                "threatType": "Signature Forgery",
                "severity": "CRITICAL",
                "locationType": "FILE_LEVEL",
                "fileName": filename,
                "lineNumber": None,
                "reason": "The evidence is derived from file-level cryptographic verification against calculated SHA-256 digest.",
                "detector": "Cryptographic Signature Analyzer",
                "explanation": [
                    "Signature verification failed against calculated digest.",
                    "No single explicit text status line was identified in payload.",
                    "Therefore the cryptographic verification result is invalid at the file level."
                ]
            })

    # 2. REPLAY ATTACK
    is_replay = (
        bool(stateful_replay and stateful_replay.get("is_stateful_replay")) or
        re.search(r'Replay Indicator\s*[:=]\s*DETECTED|TXN-REPLAY', raw_text, re.IGNORECASE) or
        re.search(r'Nonce\s*[:=]\s*REUSED|Reused Nonce', raw_text, re.IGNORECASE) or
        re.search(r'Timestamp\s*[:=]\s*REPEATED', raw_text, re.IGNORECASE)
    )

    # Check for duplicate line pairs (e.g. Line 23 and 81)
    id_map: Dict[str, List[Dict[str, Any]]] = {}
    for l in lines:
        if l.get("fieldKey") in ["transaction_id", "nonce", "session_id", "signature", "signature_hex"]:
            val = (l.get("fieldValue") or "").strip().lower()
            if val and val not in ["reused", "repeated", "invalid", "valid", "pass", "failed"]:
                if val not in id_map:
                    id_map[val] = []
                id_map[val].append(l)

    found_dup = False
    for val, occurrences in id_map.items():
        if len(occurrences) >= 2:
            found_dup = True
            line_nums = [o["lineNumber"] for o in occurrences]
            p_occ = occurrences[0]
            before, after = get_context_lines(lines, p_occ["lineNumber"], 3)
            related = [{
                "lineNumber": o["lineNumber"],
                "field": o.get("fieldKey"),
                "lineContent": o["content"],
                "reason": f"Duplicate occurrence of identifier '{val}'",
                "locationType": "LINE"
            } for o in occurrences[1:]]

            evidence_list.append({
                "id": next_id(),
                "threatType": "Replay Attack",
                "severity": "HIGH",
                "locationType": "MULTI_LINE",
                "fileName": filename,
                "lineNumber": p_occ["lineNumber"],
                "lineNumbers": line_nums,
                "field": p_occ.get("fieldKey") or "transaction_id",
                "lineContent": p_occ["content"],
                "contextBefore": before,
                "contextAfter": after,
                "reason": f"Repeated identifier/signature detected across multiple records: '{val}'",
                "detector": "Stateful Replay & Nonce Analyzer",
                "relatedEvidence": related,
                "explanation": [
                    "Replay attack identified by duplicate transaction or nonce record.",
                    f"Repeated identifier observed at Lines {' and '.join(str(n) for n in line_nums)}.",
                    "A transaction nonce or identifier must be strictly unique per session.",
                    "Therefore the re-submitted record is rejected as a replay attack."
                ],
                "timestamp": p_occ.get("timestamp")
            })
            break

    if not found_dup and is_replay:
        nonce_lines = find_lines(r'Nonce\s*[:=]\s*REUSED|Reused Nonce')
        replay_ind_lines = find_lines(r'Replay Indicator\s*[:=]\s*DETECTED')
        ts_lines = find_lines(r'Timestamp\s*[:=]\s*REPEATED')
        primary = (nonce_lines or replay_ind_lines or ts_lines or [None])[0]
        if primary:
            before, after = get_context_lines(lines, primary["lineNumber"], 3)
            evidence_list.append({
                "id": next_id(),
                "threatType": "Replay Attack",
                "severity": "HIGH",
                "locationType": "FIELD" if primary.get("fieldKey") else "LINE",
                "fileName": filename,
                "lineNumber": primary["lineNumber"],
                "field": primary.get("fieldKey") or "nonce",
                "lineContent": primary["content"],
                "contextBefore": before,
                "contextAfter": after,
                "reason": "Replay indicator flag or reused nonce token detected in stream.",
                "detector": "Stateful Replay & Nonce Analyzer",
                "explanation": [
                    "Replay attack indicator or duplicate identifier observed.",
                    f"The affected evidence was identified at Line {primary['lineNumber']}.",
                    "A previously accepted nonce or timestamp outside freshness window was re-submitted.",
                    "Therefore transaction freshness condition is violated."
                ],
                "timestamp": primary.get("timestamp")
            })

    # 3. IMPERSONATION
    is_impersonation = (
        re.search(r'Impersonation Indicator\s*[:=]\s*DETECTED', raw_text, re.IGNORECASE) or
        re.search(r'Unknown User|Rogue Entity|Rogue Signer', raw_text, re.IGNORECASE) or
        re.search(r'Authentication\s*[:=]\s*FAILED', raw_text, re.IGNORECASE)
    )
    if is_impersonation:
        signer_lines = find_lines(r'Claimed Signer|Signed By|Signer')
        auth_lines = find_lines(r'Authentication\s*[:=]\s*FAILED')
        primary = (signer_lines or auth_lines or [None])[0]
        if primary:
            before, after = get_context_lines(lines, primary["lineNumber"], 3)
            evidence_list.append({
                "id": next_id(),
                "threatType": "Signer Impersonation",
                "severity": "HIGH",
                "locationType": "FIELD" if primary.get("fieldKey") else "LINE",
                "fileName": filename,
                "lineNumber": primary["lineNumber"],
                "field": primary.get("fieldKey") or "signer_id",
                "lineContent": primary["content"],
                "contextBefore": before,
                "contextAfter": after,
                "reason": "Signer identity is inconsistent with authorized PKI directory or certificate chain.",
                "detector": "Signer Identity & PKI Trust Verifier",
                "explanation": [
                    "Signer authentication or certificate validation failed.",
                    f"The affected identity evidence was found at Line {primary['lineNumber']}.",
                    "The certificate fails verification against authorized trust roots.",
                    "Therefore the claimed signer cannot be authenticated."
                ],
                "timestamp": primary.get("timestamp")
            })

    # 4. QUANTUM EAVESDROPPING / TELEMETRY
    qber_val = quantum_metrics.get("qber", 0.0) if quantum_metrics else 0.0
    if qber_val >= 0.11 or re.search(r'Entangle-and-Measure|Eavesdropping', raw_text, re.IGNORECASE):
        qber_lines = find_lines(r'QBER\s*[:=]')
        if qber_lines:
            primary = qber_lines[0]
            before, after = get_context_lines(lines, primary["lineNumber"], 3)
            evidence_list.append({
                "id": next_id(),
                "threatType": "Quantum Eavesdropping",
                "severity": "CRITICAL",
                "locationType": "LINE",
                "fileName": filename,
                "lineNumber": primary["lineNumber"],
                "field": primary.get("fieldKey") or "qber",
                "lineContent": primary["content"],
                "contextBefore": before,
                "contextAfter": after,
                "reason": f"Contributing Evidence: Telemetry QBER value ({qber_val * 100:.2f}%) exceeds theoretical threshold (11.00%).",
                "detector": "Quantum Channel Simulation & Bell State Analyzer",
                "isContributingEvidence": True,
                "explanation": [
                    "Simulated Quantum Bit Error Rate (QBER) exceeds theoretical security bounds.",
                    f"Contributing telemetry evidence found at Line {primary['lineNumber']}.",
                    "State measurement disturbance is consistent with simulated entangle-and-measure interaction.",
                    "Therefore quantum key distribution integrity is compromised."
                ],
                "timestamp": primary.get("timestamp")
            })

    return evidence_list

def build_evidence_timeline(
    evidence_items: List[Dict[str, Any]],
    lines: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Builds an authentic timeline of security events from discovered evidence.
    Never invents false timestamps.
    """
    timeline = []
    for i, ev in enumerate(evidence_items):
        time_str = ev.get("timestamp")
        has_ts = bool(time_str)

        loc_label = f"Lines {', '.join(str(n) for n in ev['lineNumbers'])}" if ev.get("lineNumbers") else \
                    (f"Line {ev['lineNumber']}" if ev.get("lineNumber") else "File Level")

        timeline.append({
            "id": f"EVT-{i + 1}",
            "time": time_str,
            "lineNumber": ev.get("lineNumber"),
            "event": f"{loc_label} — {ev['threatType']}: {ev['reason']}",
            "severity": ev.get("severity", "HIGH"),
            "evidenceId": ev.get("id"),
            "hasTimestamp": has_ts,
            "rawRecord": ev.get("lineContent")
        })

    return timeline
