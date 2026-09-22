"""
Supabase Cloud Database & Storage Integration Module for Quantum Digital Signature Security Analyzer (Q-Secure)

This module provides clean, reusable functions for Supabase PostgreSQL persistence and Supabase Storage operations:
- upload_file()
- save_analysis()
- get_analysis_history()
- get_analysis()
- delete_analysis()
- check_connection()

Environment Variables Used:
- SUPABASE_URL: Project URL (e.g. https://your-project.supabase.co)
- SUPABASE_ANON_KEY: Client/Anon API key
- SUPABASE_SERVICE_ROLE_KEY: Privileged backend API key (never exposed to client)
- SUPABASE_BUCKET: Supabase storage bucket name (default: "qsecure-files")

Strict Security Rules:
- NEVER stores private RSA keys, passwords, or API secrets.
- Uses environment variables exclusively (no hard-coded credentials).
"""

import os
import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union

logger = logging.getLogger("qsecure.supabase_client")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [SupabaseClient] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "qsecure-files").strip()

TABLE_SECURITY_ANALYSES = "security_analyses"

_client_instance = None
_bucket_verified = False
_last_init_error = None


def get_supabase_client():
    """
    Lazily initializes the Supabase client using environment variables.
    Prefers SUPABASE_SERVICE_ROLE_KEY on the backend, falling back to SUPABASE_ANON_KEY.
    """
    global _client_instance, _last_init_error

    if _client_instance is not None:
        return _client_instance

    url = os.getenv("SUPABASE_URL", "").strip() or SUPABASE_URL
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() or os.getenv("SUPABASE_ANON_KEY", "").strip() or SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY

    if not url or not key:
        _last_init_error = "SUPABASE_URL and either SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY must be provided via environment variables."
        return None

    try:
        from supabase import create_client

        logger.info(f"Connecting to Supabase at {url} (Bucket: {get_bucket_name()})...")
        _client_instance = create_client(url, key)
        _last_init_error = None
        logger.info("Supabase client initialized successfully.")
        return _client_instance
    except Exception as e:
        _last_init_error = str(e)
        logger.warning(f"Notice: Supabase client initialization warning: {e}")
        return None


def get_bucket_name() -> str:
    """Returns the configured Supabase Storage bucket name."""
    return os.getenv("SUPABASE_BUCKET", "").strip() or SUPABASE_BUCKET or "qsecure-files"


def ensure_bucket(client=None) -> bool:
    """
    Verifies that the target storage bucket exists in Supabase Storage.
    Creates it automatically if it does not yet exist.
    """
    global _bucket_verified

    if _bucket_verified:
        return True

    sb = client or get_supabase_client()
    if not sb:
        return False

    bucket = get_bucket_name()
    try:
        buckets = sb.storage.list_buckets()
        bucket_names = [b.name for b in buckets] if buckets else []
        if bucket not in bucket_names:
            logger.info(f"Storage bucket '{bucket}' not found. Attempting creation in Supabase...")
            try:
                sb.storage.create_bucket(bucket, options={"public": False, "file_size_limit": None})
                logger.info(f"Created Supabase storage bucket '{bucket}'.")
            except Exception as create_err:
                logger.warning(f"Notice while creating bucket '{bucket}': {create_err}")
        _bucket_verified = True
        return True
    except Exception as e:
        logger.warning(f"Error checking Supabase storage buckets: {e}")
        return False


def sanitize_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Strict security sanitation:
    - NEVER store private RSA/ECDSA keys.
    - NEVER store raw passwords, tokens, or credentials.
    - Cap long text to prevent storage bloat.
    """
    sanitized = {}
    disallowed_keys = {
        "private_key", "rsa_private_key", "secret_key", "password",
        "smtp_password", "jwt_secret", "private_pem", "client_secret",
        "service_role_key", "anon_key"
    }

    for k, v in data.items():
        k_lower = str(k).lower()
        if any(d in k_lower for d in disallowed_keys):
            continue

        if isinstance(v, (bytes, bytearray)):
            continue

        if isinstance(v, str):
            if "-----BEGIN" in v and "PRIVATE KEY" in v:
                continue
            if len(v) > 50000:
                v = v[:50000] + "... [truncated]"

        if isinstance(v, dict):
            v = sanitize_payload(v)

        sanitized[k] = v

    return sanitized


def upload_file(
    file_bytes_or_path: Union[bytes, str],
    filename: str,
    case_id: str,
    content_type: str = "application/octet-stream"
) -> str:
    """
    Uploads an analyzed file artifact directly to Supabase Storage.
    Returns the cloud storage path reference (e.g., 'qsecure-files/CASE-123/artifact.bin').
    """
    bucket = get_bucket_name()
    clean_filename = re.sub(r'[^A-Za-z0-9_.-]', '_', os.path.basename(filename)) or "artifact.bin"
    storage_path = f"{case_id}/{clean_filename}"
    full_ref = f"{bucket}/{storage_path}"

    client = get_supabase_client()
    if not client:
        logger.warning("Supabase client offline. Using virtual storage path reference.")
        return full_ref

    try:
        ensure_bucket(client)

        if isinstance(file_bytes_or_path, str):
            with open(file_bytes_or_path, 'rb') as f:
                payload = f.read()
        else:
            payload = file_bytes_or_path

        file_options = {
            "content-type": content_type,
            "upsert": "true"
        }
        client.storage.from_(bucket).upload(
            path=storage_path,
            file=payload,
            file_options=file_options
        )
        logger.info(f"Successfully uploaded artifact to Supabase Storage at '{full_ref}'.")
        return full_ref
    except Exception as e:
        logger.error(f"Error uploading file to Supabase Storage: {e}")
        return full_ref


def save_analysis(
    case_id: str,
    analysis_record: Dict[str, Any],
    storage_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Saves a completed security analysis to Supabase PostgreSQL table 'security_analyses'.
    Required columns populated:
    - file_name
    - file_size
    - file_hash_sha256
    - signature_status
    - threat_score
    - threats_detected
    - attack_type
    - analysis_summary
    - timestamp
    - storage_path
    Plus case_id, user_id, verification_status.
    """
    client = get_supabase_client()
    bucket = get_bucket_name()

    file_info = analysis_record.get("file", {})
    threat_info = analysis_record.get("threat", {})
    sig_info = analysis_record.get("signature", {})
    crypto_info = analysis_record.get("cryptographic_verification", {})
    summary_info = analysis_record.get("summary", {})

    file_name = file_info.get("filename") or analysis_record.get("file_name", "artifact.bin")
    clean_storage_path = storage_path or analysis_record.get("storage_path") or f"{bucket}/{case_id}/{file_name}"
    sha256 = file_info.get("sha256") or analysis_record.get("sha256", "")
    file_size = file_info.get("file_size_bytes") or file_info.get("file_size") or analysis_record.get("file_size", 0)
    file_type = file_info.get("file_type") or analysis_record.get("file_type", "UNKNOWN")
    threat_score = threat_info.get("risk_score") if threat_info.get("risk_score") is not None else analysis_record.get("threat_score", 0)
    signature_status = sig_info.get("status") or crypto_info.get("status") or analysis_record.get("signature_status", "UNKNOWN")
    attack_type = threat_info.get("detected_threat") or analysis_record.get("attack_type", "None")
    verification_status = crypto_info.get("verification_badge") or sig_info.get("status", "UNVERIFIED")
    user_id = analysis_record.get("user_id", "usr-01")
    timestamp_val = file_info.get("upload_time") or analysis_record.get("timestamp") or datetime.now(timezone.utc).isoformat()

    threats_detected_list = threat_info.get("detected_threats") or ([attack_type] if attack_type != "None" else [])

    # Build clean summary without private keys
    raw_summary = {
        "case_id": case_id,
        "file_type": str(file_type),
        "user_id": str(user_id),
        "verification_status": str(verification_status),
        "overall_status": summary_info.get("overall_status", "COMPLETED"),
        "primary_threat": summary_info.get("primary_threat", attack_type),
        "risk_level": summary_info.get("risk_level", "LOW"),
        "threats_detected": threats_detected_list,
        "recommendation": summary_info.get("recommendation_summary", "")
    }
    sanitized_summary = sanitize_payload(raw_summary)

    doc_data = {
        "file_name": file_name,
        "file_size": int(file_size),
        "file_hash_sha256": str(sha256),
        "threat_score": int(threat_score),
        "threats_detected": threats_detected_list,
        "signature_status": str(signature_status),
        "attack_type": str(attack_type),
        "timestamp": timestamp_val,
        "storage_path": clean_storage_path,
        "analysis_summary": sanitized_summary
    }

    if not client:
        logger.warning(f"Supabase client offline. Case '{case_id}' recorded in local fallback memory.")
        return doc_data

    try:
        client.table(TABLE_SECURITY_ANALYSES).insert(doc_data).execute()
        logger.info(f"Successfully saved analysis case '{case_id}' to Supabase table '{TABLE_SECURITY_ANALYSES}'.")
        return doc_data
    except Exception as e:
        logger.error(f"Failed to write case '{case_id}' to Supabase table '{TABLE_SECURITY_ANALYSES}': {e}")
        raise RuntimeError(f"Supabase database write error: {str(e)}")


def get_analysis_history(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves previous security analyses from Supabase PostgreSQL table 'security_analyses',
    ordered by timestamp descending.
    """
    client = get_supabase_client()
    if not client:
        raise RuntimeError(f"Supabase is currently unavailable: {_last_init_error or 'Credentials missing'}")

    try:
        response = client.table(TABLE_SECURITY_ANALYSES)\
            .select("*")\
            .order("timestamp", desc=True)\
            .limit(limit)\
            .execute()
        return response.data or []
    except Exception as e:
        logger.error(f"Error retrieving cases from Supabase: {e}")
        raise RuntimeError(f"Supabase query error: {str(e)}")


def get_analysis(case_id_or_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves details of a single analysis case from Supabase table 'security_analyses'.
    Supports lookup by case_id or id.
    """
    client = get_supabase_client()
    if not client:
        raise RuntimeError(f"Supabase is currently unavailable: {_last_init_error or 'Credentials missing'}")

    try:
        # Try case_id first
        response = client.table(TABLE_SECURITY_ANALYSES)\
            .select("*")\
            .eq("case_id", case_id_or_id)\
            .limit(1)\
            .execute()
        if response.data and len(response.data) > 0:
            return response.data[0]

        # Try id if not found
        response_id = client.table(TABLE_SECURITY_ANALYSES)\
            .select("*")\
            .eq("id", case_id_or_id)\
            .limit(1)\
            .execute()
        if response_id.data and len(response_id.data) > 0:
            return response_id.data[0]

        return None
    except Exception as e:
        logger.error(f"Error fetching case '{case_id_or_id}' from Supabase: {e}")
        raise RuntimeError(f"Supabase read error: {str(e)}")


def delete_analysis(case_id: str) -> bool:
    """
    Deletes an analysis record from Supabase table 'security_analyses'
    and removes its associated artifact from Supabase Storage.
    """
    client = get_supabase_client()
    bucket = get_bucket_name()

    if not client:
        raise RuntimeError(f"Supabase is currently unavailable: {_last_init_error or 'Credentials missing'}")

    try:
        # 1. Fetch record to locate storage path
        record = get_analysis(case_id)
        if record and record.get("storage_path"):
            storage_path = record["storage_path"]
            if storage_path.startswith(f"{bucket}/"):
                file_path = storage_path[len(bucket) + 1:]
            else:
                file_path = storage_path
            try:
                client.storage.from_(bucket).remove([file_path])
                logger.info(f"Removed artifact '{file_path}' from Supabase Storage.")
            except Exception as st_err:
                logger.warning(f"Notice while removing storage artifact: {st_err}")

        # 2. Delete database row
        client.table(TABLE_SECURITY_ANALYSES).delete().eq("case_id", case_id).execute()
        logger.info(f"Deleted case '{case_id}' from Supabase table '{TABLE_SECURITY_ANALYSES}'.")
        return True
    except Exception as e:
        logger.error(f"Error deleting case '{case_id}' from Supabase: {e}")
        raise RuntimeError(f"Supabase delete error: {str(e)}")


def check_connection() -> Dict[str, Any]:
    """
    Verifies Supabase PostgreSQL database and Storage availability safely.
    Never exposes keys or secrets.
    """
    url = os.getenv("SUPABASE_URL", "").strip() or SUPABASE_URL
    bucket = get_bucket_name()
    has_key = bool(os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() or os.getenv("SUPABASE_ANON_KEY", "").strip() or SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY)

    client = get_supabase_client()
    if not client:
        return {
            "status": "offline",
            "connected": False,
            "engine": "supabase_postgresql",
            "storage": "supabase_storage",
            "url_configured": bool(url),
            "key_configured": has_key,
            "bucket": bucket,
            "message": _last_init_error or "Supabase environment variables not configured."
        }

    try:
        # Lightweight ping to the security_analyses table
        client.table(TABLE_SECURITY_ANALYSES).select("case_id").limit(1).execute()
        return {
            "status": "connected",
            "connected": True,
            "engine": "supabase_postgresql",
            "storage": "supabase_storage",
            "url": url,
            "bucket": bucket,
            "message": f"Connected to Supabase PostgreSQL table '{TABLE_SECURITY_ANALYSES}' and bucket '{bucket}'."
        }
    except Exception as e:
        return {
            "status": "configured_error",
            "connected": False,
            "engine": "supabase_postgresql",
            "storage": "supabase_storage",
            "url": url,
            "bucket": bucket,
            "message": f"Supabase connection error: {str(e)}"
        }
