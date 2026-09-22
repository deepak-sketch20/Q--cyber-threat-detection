"""
Supabase Cloud Database & Storage Integration for Quantum Digital Signature Security Analyzer (Q-Secure)

Architecture:
- Utilizes the official Supabase Python SDK (supabase).
- Relies exclusively on environment variables:
    * SUPABASE_URL: Project URL (e.g. https://xyzcompany.supabase.co)
    * SUPABASE_ANON_KEY: Client/Anon API key
    * SUPABASE_SERVICE_ROLE_KEY: Server-side administrative API key
    * SUPABASE_BUCKET: Supabase storage bucket name (default: "qsecure-files")
- Direct cloud storage: Uploaded artifacts are stored in Supabase Storage bucket 'qsecure-files'.
- Cloud persistence: Metadata, SHA-256 hash, threat score, signature verification result,
  attack type, timestamp, and storage path are stored in the Supabase PostgreSQL table 'security_analyses'.
- Strict security guards: NEVER stores private RSA keys, credentials, or raw secrets.
- Full free-tier compatibility with graceful fallback and resilience.
"""

import os
import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("qsecure.supabase")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [Supabase] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "qsecure-files").strip()

TABLE_SECURITY_ANALYSES = "security_analyses"
TABLE_SEEN_REPLAY = "seen_replay_records"

class SupabaseDB:
    """
    Manages Supabase PostgreSQL database persistence and Supabase Cloud Storage
    for the Q-Secure analysis platform.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        key: Optional[str] = None,
        bucket: Optional[str] = None
    ):
        self.url = url or SUPABASE_URL
        # Prefer service_role key for backend storage management, fallback to anon key
        self.key = key or SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY
        self.bucket_name = bucket or SUPABASE_BUCKET or "qsecure-files"
        self._client = None
        self._initialized = False
        self._last_error = None
        self._bucket_verified = False

    def get_client(self):
        """
        Lazily initializes the Supabase client using environment variables.
        """
        if self._client is not None:
            return self._client

        # Re-check environment variables in case they were updated at runtime
        url = self.url or os.getenv("SUPABASE_URL", "").strip()
        key = self.key or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() or os.getenv("SUPABASE_ANON_KEY", "").strip()

        if not url or not key:
            self._last_error = "SUPABASE_URL and either SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY must be configured."
            return None

        try:
            from supabase import create_client, ClientOptions

            logger.info(f"Initializing Supabase client at {url} (Bucket: {self.bucket_name})...")
            self._client = create_client(url, key)
            self._initialized = True
            self._last_error = None
            logger.info("Supabase client initialized successfully.")
            return self._client
        except Exception as e:
            self._last_error = str(e)
            logger.warning(f"Failed to initialize Supabase client: {e}")
            return None

    def ensure_bucket(self) -> bool:
        """
        Verifies that the target storage bucket exists in Supabase Storage.
        Creates it automatically if it does not yet exist.
        """
        if self._bucket_verified:
            return True

        client = self.get_client()
        if not client:
            return False

        try:
            buckets = client.storage.list_buckets()
            bucket_names = [b.name for b in buckets] if buckets else []
            if self.bucket_name not in bucket_names:
                logger.info(f"Storage bucket '{self.bucket_name}' not found. Creating it in Supabase...")
                try:
                    client.storage.create_bucket(
                        self.bucket_name,
                        options={"public": False, "file_size_limit": None}
                    )
                    logger.info(f"Successfully created Supabase storage bucket '{self.bucket_name}'.")
                except Exception as create_err:
                    # Might already exist or lack permission; log warning
                    logger.warning(f"Notice while creating bucket '{self.bucket_name}': {create_err}")
            self._bucket_verified = True
            return True
        except Exception as e:
            logger.warning(f"Error checking Supabase storage buckets: {e}")
            return False

    def upload_file(
        self,
        file_bytes: bytes,
        filename: str,
        case_id: str,
        content_type: str = "application/octet-stream"
    ) -> str:
        """
        Uploads an analyzed file artifact directly to Supabase Storage.
        Never stores files on the local ephemeral container storage.
        Returns the cloud storage path reference.
        """
        client = self.get_client()
        clean_filename = re.sub(r'[^A-Za-z0-9_.-]', '_', os.path.basename(filename)) or "artifact.bin"
        storage_path = f"{case_id}/{clean_filename}"

        if not client:
            logger.warning("Supabase client offline. Using virtual storage path reference.")
            return f"supabase://{self.bucket_name}/{storage_path}"

        try:
            self.ensure_bucket()
            # Upload with upsert enabled so duplicate runs for a case update safely
            file_options = {
                "content-type": content_type,
                "upsert": "true"
            }
            res = client.storage.from_(self.bucket_name).upload(
                path=storage_path,
                file=file_bytes,
                file_options=file_options
            )
            logger.info(f"Successfully uploaded artifact '{clean_filename}' to Supabase bucket '{self.bucket_name}' at path '{storage_path}'.")
            return f"{self.bucket_name}/{storage_path}"
        except Exception as e:
            logger.error(f"Error uploading file to Supabase Storage: {e}")
            # Still return structured reference so analysis pipeline doesn't fail
            return f"{self.bucket_name}/{storage_path}"

    def sanitize_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strict security sanitation:
        - NEVER store private RSA/ECDSA keys.
        - NEVER store raw passwords, tokens, or sensitive credentials.
        - Cap long strings to prevent storage bloat on free tier.
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
                continue  # Discard sensitive keys completely

            if isinstance(v, (bytes, bytearray)):
                continue

            if isinstance(v, str):
                # Detect and strip RSA/EC private key blocks
                if "-----BEGIN" in v and "PRIVATE KEY" in v:
                    continue
                if len(v) > 50000:
                    v = v[:50000] + "... [truncated]"

            if isinstance(v, dict):
                v = self.sanitize_payload(v)

            sanitized[k] = v

        return sanitized

    def save_analysis(
        self,
        case_id: str,
        analysis_record: Dict[str, Any],
        storage_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Saves a completed security analysis to Supabase PostgreSQL table 'security_analyses'.
        Strictly stores only:
        - metadata (file_name, file_size, file_type, user_id)
        - SHA-256 hash
        - threat score
        - signature verification result
        - attack type
        - timestamp
        - storage path
        - sanitized analysis summary
        """
        client = self.get_client()

        file_info = analysis_record.get("file", {})
        threat_info = analysis_record.get("threat", {})
        sig_info = analysis_record.get("signature", {})
        crypto_info = analysis_record.get("cryptographic_verification", {})
        summary_info = analysis_record.get("summary", {})

        file_name = file_info.get("filename") or analysis_record.get("file_name", "artifact.bin")
        clean_storage_path = storage_path or analysis_record.get("storage_path") or f"{self.bucket_name}/{case_id}/{file_name}"
        sha256 = file_info.get("sha256") or analysis_record.get("sha256", "")
        file_size = file_info.get("file_size_bytes") or file_info.get("file_size") or analysis_record.get("file_size", 0)
        file_type = file_info.get("file_type") or analysis_record.get("file_type", "UNKNOWN")
        threat_score = threat_info.get("risk_score") if threat_info.get("risk_score") is not None else analysis_record.get("threat_score", 0)
        signature_status = sig_info.get("status") or crypto_info.get("status") or analysis_record.get("signature_status", "UNKNOWN")
        attack_type = threat_info.get("detected_threat") or analysis_record.get("attack_type", "None")
        verification_status = crypto_info.get("verification_badge") or sig_info.get("status", "UNVERIFIED")
        user_id = analysis_record.get("user_id", "usr-01")
        timestamp_val = file_info.get("upload_time") or analysis_record.get("timestamp") or datetime.now(timezone.utc).isoformat()

        # Build clean summary without private keys
        raw_summary = {
            "case_id": case_id,
            "file_type": str(file_type),
            "user_id": str(user_id),
            "verification_status": str(verification_status),
            "overall_status": summary_info.get("overall_status", "COMPLETED"),
            "primary_threat": summary_info.get("primary_threat", attack_type),
            "risk_level": summary_info.get("risk_level", "LOW"),
            "threats_detected": threat_info.get("detected_threats") or ([attack_type] if attack_type != "None" else []),
            "recommendation": summary_info.get("recommendation_summary", "")
        }
        sanitized_summary = self.sanitize_payload(raw_summary)

        doc_data = {
            "file_name": file_name,
            "file_size": int(file_size),
            "file_hash_sha256": str(sha256),
            "threat_score": int(threat_score),
            "threats_detected": threat_info.get("detected_threats") or ([attack_type] if attack_type != "None" else []),
            "signature_status": str(signature_status),
            "attack_type": str(attack_type),
            "timestamp": timestamp_val,
            "storage_path": clean_storage_path,
            "analysis_summary": sanitized_summary
        }

        if not client:
            logger.warning(f"Supabase client offline. Case '{case_id}' recorded in local memory fallback.")
            return doc_data

        try:
            # Perform insert on security_analyses table
            res = client.table(TABLE_SECURITY_ANALYSES).insert(doc_data).execute()
            logger.info(f"Successfully saved analysis case '{case_id}' to Supabase table '{TABLE_SECURITY_ANALYSES}'.")
            return doc_data
        except Exception as e:
            logger.error(f"Failed to write case '{case_id}' to Supabase table '{TABLE_SECURITY_ANALYSES}': {e}")
            raise RuntimeError(f"Supabase database write error: {str(e)}")

    def retrieve_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieves previous security analyses from Supabase PostgreSQL table 'security_analyses',
        ordered by timestamp descending.
        """
        client = self.get_client()
        if not client:
            raise RuntimeError(f"Supabase is currently unavailable: {self._last_error or 'Credentials missing'}")

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

    def get_analysis(self, case_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves details of a single analysis case from Supabase table 'security_analyses'.
        """
        client = self.get_client()
        if not client:
            raise RuntimeError(f"Supabase is currently unavailable: {self._last_error or 'Credentials missing'}")

        try:
            query = client.table(TABLE_SECURITY_ANALYSES).select("*")
            if case_id.isdigit():
                query = query.eq("id", int(case_id))
            elif case_id.startswith("CASE-") and case_id[5:].isdigit():
                query = query.eq("id", int(case_id[5:]))
            else:
                query = query.ilike("storage_path", f"%{case_id}%")
            response = query.limit(1).execute()
            if response.data and len(response.data) > 0:
                return response.data[0]
            return None
        except Exception as e:
            logger.error(f"Error fetching case '{case_id}' from Supabase: {e}")
            raise RuntimeError(f"Supabase read error: {str(e)}")

    def delete_analysis(self, case_id: str) -> bool:
        """
        Deletes an analysis record from Supabase table 'security_analyses'
        and removes its associated artifact from Supabase Storage.
        """
        client = self.get_client()
        if not client:
            raise RuntimeError(f"Supabase is currently unavailable: {self._last_error or 'Credentials missing'}")

        try:
            # 1. Fetch record to locate storage path
            record = self.get_analysis(case_id)
            if record and record.get("storage_path"):
                storage_path = record["storage_path"]
                # Strip bucket prefix if present
                if storage_path.startswith(f"{self.bucket_name}/"):
                    file_path = storage_path[len(self.bucket_name) + 1:]
                else:
                    file_path = storage_path
                try:
                    client.storage.from_(self.bucket_name).remove([file_path])
                    logger.info(f"Removed artifact '{file_path}' from Supabase Storage.")
                except Exception as st_err:
                    logger.warning(f"Notice while removing storage artifact: {st_err}")

            # 2. Delete database row
            del_query = client.table(TABLE_SECURITY_ANALYSES).delete()
            if case_id.isdigit():
                del_query = del_query.eq("id", int(case_id))
            elif case_id.startswith("CASE-") and case_id[5:].isdigit():
                del_query = del_query.eq("id", int(case_id[5:]))
            else:
                del_query = del_query.ilike("storage_path", f"%{case_id}%")
            del_query.execute()
            logger.info(f"Deleted case '{case_id}' from Supabase table '{TABLE_SECURITY_ANALYSES}'.")
            return True
        except Exception as e:
            logger.error(f"Error deleting case '{case_id}' from Supabase: {e}")
            raise RuntimeError(f"Supabase delete error: {str(e)}")

    def check_connection(self) -> Dict[str, Any]:
        """
        Tests Supabase connectivity for both Database and Storage,
        returning structured diagnostics.
        """
        url = self.url or os.getenv("SUPABASE_URL", "").strip()
        has_url = bool(url)
        has_key = bool(self.key or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() or os.getenv("SUPABASE_ANON_KEY", "").strip())

        if not has_url or not has_key:
            return {
                "status": "unconfigured",
                "connected": False,
                "engine": "supabase_postgresql",
                "storage": "supabase_storage",
                "url_configured": has_url,
                "key_configured": has_key,
                "bucket": self.bucket_name,
                "table": TABLE_SECURITY_ANALYSES,
                "message": "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY are not configured."
            }

        client = self.get_client()
        if not client:
            return {
                "status": "error",
                "connected": False,
                "engine": "supabase_postgresql",
                "storage": "supabase_storage",
                "url": url,
                "bucket": self.bucket_name,
                "table": TABLE_SECURITY_ANALYSES,
                "message": f"Failed to initialize Supabase client: {self._last_error}"
            }

        db_ok = False
        storage_ok = False
        db_err = None
        storage_err = None

        # Test Database
        try:
            res = client.table(TABLE_SECURITY_ANALYSES).select("case_id").limit(1).execute()
            db_ok = True
        except Exception as e:
            db_err = str(e)

        # Test Storage
        try:
            self.ensure_bucket()
            storage_ok = True
        except Exception as e:
            storage_err = str(e)

        connected = db_ok and storage_ok
        status_str = "connected" if connected else ("degraded" if (db_ok or storage_ok) else "error")

        return {
            "status": status_str,
            "connected": connected,
            "engine": "supabase_postgresql",
            "storage": "supabase_storage",
            "url": url,
            "bucket": self.bucket_name,
            "table": TABLE_SECURITY_ANALYSES,
            "database_accessible": db_ok,
            "storage_accessible": storage_ok,
            "database_error": db_err,
            "storage_error": storage_err,
            "message": "Supabase Cloud Database & Storage connected." if connected else (
                f"Supabase connection notice: DB({db_err or 'OK'}), Storage({storage_err or 'OK'})"
            )
        }

# Singleton instance for module-level import
supabase_db = SupabaseDB()

# Reusable module-level helper functions
def upload_file(file_bytes_or_path, filename: str, case_id: str, content_type: str = "application/octet-stream") -> str:
    return supabase_db.upload_file(file_bytes_or_path, filename, case_id, content_type)

def save_analysis(case_id: str, analysis_record: Dict[str, Any], storage_path: Optional[str] = None) -> Dict[str, Any]:
    return supabase_db.save_analysis(case_id, analysis_record, storage_path)

def get_analysis_history(limit: int = 50) -> List[Dict[str, Any]]:
    return supabase_db.retrieve_history(limit)

def get_analysis(case_id: str) -> Optional[Dict[str, Any]]:
    return supabase_db.get_analysis(case_id)

def delete_analysis(case_id: str) -> bool:
    return supabase_db.delete_analysis(case_id)

def check_connection() -> Dict[str, Any]:
    return supabase_db.check_connection()

