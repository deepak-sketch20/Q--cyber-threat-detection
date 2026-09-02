"""
Quantum Digital Signature Security Analyzer
Audit Logger Module: Tamper-Evident Cryptographic Hash Chaining
Provides deterministic hash-chained audit trails where each event includes:
  event_hash = SHA256(previous_event_hash + timestamp + event + status)
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

def create_case_id() -> str:
    """Generates a unique forensic Case ID."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"CASE-{now_str}-{short_uuid}"

def build_tamper_evident_audit_chain(raw_events: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Constructs a chained cryptographic log sequence.
    Label: 'Prototype tamper-evident audit chain'.
    """
    genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    current_prev_hash = genesis_hash
    chained_logs = []

    for item in raw_events:
        time_val = item.get("time", datetime.now().strftime("%H:%M:%S.%f")[:-3])
        event_val = item.get("event", "")
        status_val = item.get("status", "SUCCESS")

        payload_to_hash = f"{current_prev_hash}|{time_val}|{event_val}|{status_val}".encode('utf-8')
        event_hash = hashlib.sha256(payload_to_hash).hexdigest()

        chained_logs.append({
            "time": time_val,
            "event": event_val,
            "status": status_val,
            "previous_hash": current_prev_hash[:12] + "...",
            "event_hash": event_hash[:16] + "...",
            "full_event_hash": event_hash
        })
        current_prev_hash = event_hash

    return chained_logs
