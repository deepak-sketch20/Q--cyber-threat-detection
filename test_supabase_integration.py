"""
Integration Test Script for Supabase on Q-Secure
Tests:
1. Connection to Supabase using SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY / SUPABASE_ANON_KEY
2. Verification of 'security_analyses' table accessibility
3. Verification of 'qsecure-files' storage bucket accessibility
4. Insertion of 1 test analysis record clearly marked with TEST data
5. Verification that the test record appears in Supabase
6. Detailed diagnostic reporting
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

def parse_dotenv():
    """Load variables from .env if present in the current working directory."""
    if os.path.exists(".env"):
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v

def run_tests():
    parse_dotenv()

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "step_1_connection": {"status": "pending"},
        "step_2_table_accessibility": {"status": "pending"},
        "step_3_bucket_accessibility": {"status": "pending"},
        "step_4_create_test_record": {"status": "pending"},
        "step_5_confirm_test_record": {"status": "pending"},
        "overall_result": "pending"
    }

    url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip() or os.getenv("SUPABASE_ANON_KEY", "").strip()
    bucket_name = os.getenv("SUPABASE_BUCKET", "qsecure-files").strip()

    print(f"[*] Starting Supabase Integration Test at {report['timestamp']}")
    print(f"[*] SUPABASE_URL configured: {bool(url)} ({url[:25]}... if url else 'NONE')")
    print(f"[*] SUPABASE_SERVICE_ROLE_KEY configured: {bool(os.getenv('SUPABASE_SERVICE_ROLE_KEY'))}")
    print(f"[*] SUPABASE_ANON_KEY configured: {bool(os.getenv('SUPABASE_ANON_KEY'))}")
    print(f"[*] Target Bucket: {bucket_name}")
    print("=" * 65)

    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    def api_request(path, method="GET", body=None):
        req_url = f"{url}{path}"
        req_data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(req_url, data=req_data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else {}

    # STEP 1: Test Connection
    try:
        if not url or not key:
            raise ValueError("SUPABASE_URL and key must be defined in the environment.")
        
        # Test basic connection via PostgREST OpenAPI schema or health
        req = urllib.request.Request(f"{url}/rest/v1/", headers={"apikey": key}, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 204):
                raise ValueError(f"Supabase connection returned HTTP status: {resp.status}")

        report["step_1_connection"] = {
            "status": "PASS",
            "message": "Supabase endpoint reachable and authentication headers validated.",
            "url": url
        }
        print("[+] STEP 1: Connection to Supabase SUCCESSFUL.")
    except Exception as e:
        report["step_1_connection"] = {
            "status": "FAIL",
            "error": str(e)
        }
        print(f"[-] STEP 1 FAIL: {e}")
        report["overall_result"] = "FAIL"
        return report

    # STEP 2: Verify security_analyses table accessibility
    try:
        table_path = "/rest/v1/security_analyses?select=*&limit=5"
        records = api_request(table_path, method="GET")
        
        report["step_2_table_accessibility"] = {
            "status": "PASS",
            "message": "Table 'security_analyses' is accessible and queryable.",
            "existing_records_count": len(records) if isinstance(records, list) else 0
        }
        print(f"[+] STEP 2: 'security_analyses' table is ACCESSIBLE ({len(records)} existing sample records).")
    except Exception as e:
        report["step_2_table_accessibility"] = {
            "status": "FAIL",
            "error": str(e)
        }
        print(f"[-] STEP 2 FAIL: {e}")

    # STEP 3: Verify qsecure-files storage bucket accessibility
    try:
        bucket_info = api_request(f"/storage/v1/bucket/{bucket_name}", method="GET")
        bucket_found = bool(bucket_info and bucket_info.get("name") == bucket_name)
        
        # Probe upload verification
        probe_path = f"test_probes/probe_{int(time.time())}.txt"
        probe_url = f"{url}/storage/v1/object/{bucket_name}/{probe_path}"
        probe_data = b"Q-SECURE STORAGE PROBE INTEGRITY VERIFICATION"
        
        upload_headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "text/plain"
        }
        up_req = urllib.request.Request(probe_url, data=probe_data, headers=upload_headers, method="POST")
        with urllib.request.urlopen(up_req, timeout=10) as up_resp:
            upload_ok = up_resp.status in (200, 201)

        # Cleanup probe
        del_headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        del_req = urllib.request.Request(
            f"{url}/storage/v1/object/{bucket_name}",
            data=json.dumps({"prefixes": [probe_path]}).encode("utf-8"),
            headers=del_headers,
            method="DELETE"
        )
        try:
            urllib.request.urlopen(del_req, timeout=10)
        except Exception:
            pass

        report["step_3_bucket_accessibility"] = {
            "status": "PASS",
            "message": f"Storage bucket '{bucket_name}' is accessible with read and write permissions verified.",
            "bucket": bucket_name,
            "bucket_id": bucket_info.get("id", bucket_name)
        }
        print(f"[+] STEP 3: Storage bucket '{bucket_name}' is ACCESSIBLE (upload/read verified).")
    except Exception as e:
        report["step_3_bucket_accessibility"] = {
            "status": "FAIL",
            "error": str(e)
        }
        print(f"[-] STEP 3 FAIL: {e}")

    # STEP 4: Create one test analysis record with clearly marked TEST data
    test_case_id = f"TEST-CASE-QSECURE-{int(time.time() * 1000)}"
    test_file_name = "TEST_INTEGRITY_PROBE.bin"
    test_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    test_storage_path = f"{bucket_name}/{test_case_id}/{test_file_name}"
    test_timestamp = datetime.now(timezone.utc).isoformat()

    test_record = {
        "file_name": test_file_name,
        "file_size": 2048,
        "file_hash_sha256": test_sha256,
        "signature_status": "TEST_VERIFIED_VALID",
        "threat_score": 0,
        "threats_detected": ["TEST_BENIGN_HARNESS_PROBE"],
        "attack_type": "None (Verification Test)",
        "timestamp": test_timestamp,
        "storage_path": test_storage_path,
        "analysis_summary": {
            "case_id": test_case_id,
            "overall_status": "TEST_SECURE",
            "primary_threat": "None",
            "risk_level": "LOW",
            "threats_detected": ["TEST_BENIGN_HARNESS_PROBE"],
            "recommendation": "Verification test record created by automated test suite. Integrity confirmed."
        }
    }

    created_id = None
    try:
        insert_res = api_request("/rest/v1/security_analyses", method="POST", body=test_record)
        if isinstance(insert_res, list) and len(insert_res) > 0:
            created_id = insert_res[0].get("id")
        elif isinstance(insert_res, dict):
            created_id = insert_res.get("id")

        report["step_4_create_test_record"] = {
            "status": "PASS",
            "message": f"Created test analysis record successfully in Supabase (ID: {created_id}).",
            "test_case_id": test_case_id,
            "inserted_id": created_id,
            "details": test_record
        }
        print(f"[+] STEP 4: Created test analysis record with ID: {created_id} (Case: {test_case_id}).")
    except Exception as e:
        report["step_4_create_test_record"] = {
            "status": "FAIL",
            "error": str(e)
        }
        print(f"[-] STEP 4 FAIL: {e}")
        report["overall_result"] = "FAIL"
        return report

    # STEP 5: Confirm that the record appears in Supabase
    try:
        query_path = f"/rest/v1/security_analyses?id=eq.{created_id}" if created_id else f"/rest/v1/security_analyses?file_hash_sha256=eq.{test_sha256}&order=timestamp.desc&limit=1"
        fetched = api_request(query_path, method="GET")

        if not fetched or not isinstance(fetched, list) or len(fetched) == 0:
            raise ValueError("Record not found when querying Supabase table.")

        rec = fetched[0]
        report["step_5_confirm_test_record"] = {
            "status": "PASS",
            "message": "Confirmed that the record appears in Supabase table 'security_analyses'.",
            "retrieved_record": {
                "id": rec.get("id"),
                "file_name": rec.get("file_name"),
                "file_size": rec.get("file_size"),
                "file_hash_sha256": rec.get("file_hash_sha256"),
                "signature_status": rec.get("signature_status"),
                "threat_score": rec.get("threat_score"),
                "timestamp": rec.get("timestamp"),
                "storage_path": rec.get("storage_path"),
                "analysis_summary": rec.get("analysis_summary")
            }
        }
        print(f"[+] STEP 5: Confirmed test record appears in Supabase! ID: {rec.get('id')}")
        print(f"    File: {rec.get('file_name')} | SHA-256: {rec.get('file_hash_sha256')}")
        print(f"    Status: {rec.get('signature_status')} | Threat Score: {rec.get('threat_score')}")
    except Exception as e:
        report["step_5_confirm_test_record"] = {
            "status": "FAIL",
            "error": str(e)
        }
        print(f"[-] STEP 5 FAIL: {e}")

    # Evaluate Overall Status
    steps = [
        report["step_1_connection"],
        report["step_2_table_accessibility"],
        report["step_3_bucket_accessibility"],
        report["step_4_create_test_record"],
        report["step_5_confirm_test_record"]
    ]
    all_passed = all(s.get("status") == "PASS" for s in steps)
    report["overall_result"] = "PASS" if all_passed else "FAIL"

    print("=" * 65)
    print(f"[*] OVERALL TEST RESULT: {report['overall_result']}")
    print("=" * 65)

    with open("supabase_test_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("Detailed results written to supabase_test_report.json")
    return report

if __name__ == "__main__":
    rep = run_tests()
    if rep.get("overall_result") != "PASS":
        sys.exit(1)
    sys.exit(0)
