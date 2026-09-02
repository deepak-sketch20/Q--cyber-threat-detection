"""
Quantum Digital Signature Security Analyzer
Replay Store Module: Stateful Local Cache & Timestamp Freshness Engine
Uses SQLite to track nonces, transaction IDs, session IDs, message hashes, and timestamps.
"""

import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'replay_store.db')
DEFAULT_FRESHNESS_WINDOW_SECONDS = 120  # Configurable freshness constant (+/- 120 seconds)

def _get_db_connection():
    """Initializes and returns SQLite connection with schema."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS seen_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_type TEXT,
            record_value TEXT UNIQUE,
            signer_id TEXT,
            message_hash TEXT,
            file_name TEXT,
            first_seen REAL,
            last_seen REAL,
            hit_count INTEGER DEFAULT 1
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_rec_val ON seen_records(record_value)')
    conn.commit()
    return conn

def check_and_record_stateful_replay(
    nonce: Optional[str],
    txn_id: Optional[str],
    session_id: Optional[str],
    message_hash: str,
    signer_id: Optional[str] = None,
    filename: str = "",
    timestamp_str: Optional[str] = None,
    freshness_window: int = DEFAULT_FRESHNESS_WINDOW_SECONDS
) -> Dict[str, Any]:
    """
    Checks if any key identifiers (nonce, transaction ID, session ID, message hash)
    were previously processed in the stateful local store.
    
    Returns a comprehensive verdict:
      - is_stateful_replay (bool)
      - stateful_replay_type ('STATEFUL_REPLAY_DETECTED' | 'FRESH_TRANSACTION' | 'STALE_TIMESTAMP')
      - matched_identifiers (list)
      - hit_count (int)
      - first_seen_time (str)
      - timestamp_freshness ('FRESH' | 'STALE' | 'UNKNOWN')
      - freshness_delta_seconds (float)
    """
    now_ts = time.time()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    matched_items = []
    max_hits = 0
    first_seen_str = None
    
    conn = _get_db_connection()
    try:
        # Check identifiers
        identifiers_to_check = []
        if nonce and nonce.upper() not in ["REUSED", "UNKNOWN", "NONE", "N/A", ""]:
            identifiers_to_check.append(("NONCE", f"NONCE:{nonce.strip()}"))
        if txn_id and txn_id.upper() not in ["TXN-REPLAY-001", "TXN-REPLAY", "UNKNOWN", "NONE", ""]:
            identifiers_to_check.append(("TXN_ID", f"TXN:{txn_id.strip()}"))
        if session_id and session_id.upper() not in ["REUSED", "UNKNOWN", "NONE", ""]:
            identifiers_to_check.append(("SESSION_ID", f"SESS:{session_id.strip()}"))
        if message_hash:
            identifiers_to_check.append(("MESSAGE_HASH", f"HASH:{message_hash.strip()}"))

        for id_type, id_val in identifiers_to_check:
            cur = conn.cursor()
            cur.execute("SELECT first_seen, last_seen, hit_count FROM seen_records WHERE record_value = ?", (id_val,))
            row = cur.fetchone()
            if row:
                f_seen, l_seen, count = row
                matched_items.append({
                    "type": id_type,
                    "value": id_val.split(":", 1)[1],
                    "first_seen": datetime.fromtimestamp(f_seen, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "hit_count": count + 1
                })
                max_hits = max(max_hits, count + 1)
                if not first_seen_str:
                    first_seen_str = datetime.fromtimestamp(f_seen, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                # Update hit count
                conn.execute(
                    "UPDATE seen_records SET last_seen = ?, hit_count = hit_count + 1 WHERE record_value = ?",
                    (now_ts, id_val)
                )
            else:
                # Insert new record
                conn.execute(
                    "INSERT INTO seen_records (record_type, record_value, signer_id, message_hash, file_name, first_seen, last_seen, hit_count) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                    (id_type, id_val, signer_id or "unknown", message_hash, filename, now_ts, now_ts)
                )
        conn.commit()
    except Exception as e:
        print(f"Replay store DB error: {e}")
    finally:
        conn.close()

    # Timestamp freshness analysis
    timestamp_freshness = "UNKNOWN"
    freshness_delta = 0.0
    if timestamp_str and timestamp_str.upper() not in ["REPEATED", "STALE", "NONE", ""]:
        try:
            # Parse ISO 8601 or common formats
            ts_cleaned = timestamp_str.replace("Z", "+00:00")
            parsed_dt = datetime.fromisoformat(ts_cleaned)
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
            delta = abs((datetime.now(timezone.utc) - parsed_dt).total_seconds())
            freshness_delta = round(delta, 1)
            if delta > freshness_window:
                timestamp_freshness = "STALE"
            else:
                timestamp_freshness = "FRESH"
        except Exception:
            timestamp_freshness = "PARSE_ERROR"

    is_stateful_replay = len(matched_items) > 0
    if is_stateful_replay:
        verdict_type = "STATEFUL_REPLAY_DETECTED"
    elif timestamp_freshness == "STALE":
        verdict_type = "STALE_TIMESTAMP"
    else:
        verdict_type = "FRESH_TRANSACTION"

    return {
        "is_stateful_replay": is_stateful_replay,
        "stateful_replay_type": verdict_type,
        "matched_identifiers": matched_items,
        "hit_count": max_hits if is_stateful_replay else 1,
        "first_seen": first_seen_str or now_str,
        "freshness_window_seconds": freshness_window,
        "timestamp_freshness": timestamp_freshness,
        "freshness_delta_seconds": freshness_delta,
        "store_type": "SQLite Local Replay Cache"
    }

def clear_replay_store():
    """Resets the stateful replay database."""
    conn = _get_db_connection()
    try:
        conn.execute("DELETE FROM seen_records")
        conn.commit()
    finally:
        conn.close()
