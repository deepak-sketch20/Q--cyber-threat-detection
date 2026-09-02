"""
Quantum Digital Signature Security Analyzer
File Analyzer Module: Security-Hardened Ingestion, SHA-256 Hash & Forensic Structure Inspection
Supports: .txt, .json, .csv, .pdf, .p7s, .p7m, .pem, .der, .cer, .crt, .asc, .log
"""

import os
import json
import csv
import io
import re
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def compute_sha256_bytes(file_bytes: bytes) -> str:
    """Computes SHA-256 hex digest of raw uploaded bytes."""
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    return hasher.hexdigest()

def detect_mime_and_magic(file_bytes: bytes, filename: str) -> Dict[str, str]:
    """Inspects magic byte headers safely without external system dependencies."""
    ext = os.path.splitext(filename)[1].lower()
    magic = "Unknown"
    mime = "application/octet-stream"

    if file_bytes.startswith(b'%PDF-'):
        magic = "PDF Magic Header (%PDF-)"
        mime = "application/pdf"
    elif file_bytes.startswith(b'-----BEGIN CERTIFICATE-----') or file_bytes.startswith(b'-----BEGIN PKCS7-----') or file_bytes.startswith(b'-----BEGIN RSA'):
        magic = "PEM Header (ASCII Armor)"
        mime = "application/x-pem-file"
    elif file_bytes.startswith(b'-----BEGIN PGP'):
        magic = "OpenPGP ASCII Armor"
        mime = "application/pgp-signature"
    elif len(file_bytes) > 2 and file_bytes[0] == 0x30 and file_bytes[1] in [0x82, 0x81, 0x83]:
        magic = "ASN.1 DER Sequence (0x30)"
        mime = "application/pkcs7-signature" if ext in ['.p7s', '.p7m'] else "application/x-x509-ca-cert"
    elif ext == '.json':
        mime = "application/json"
        magic = "JSON Data Stream"
    elif ext == '.csv':
        mime = "text/csv"
        magic = "CSV Delimited Stream"
    elif ext in ['.txt', '.log']:
        mime = "text/plain"
        magic = "UTF-8 / ASCII Text Stream"

    return {"magic": magic, "mime": mime}

def inspect_pdf_signatures(file_bytes: bytes) -> Dict[str, Any]:
    """
    Inspects PDF signature dictionary, ByteRange, revisions, and incremental modifications.
    """
    has_pdf_sig = False
    sig_fields = []
    byte_ranges = []
    revisions_count = 1
    changes_after_sig = "UNKNOWN"
    details = "Standard PDF document."

    try:
        # Check for PDF End of File / Incremental updates
        eof_matches = list(re.finditer(rb'%%EOF', file_bytes))
        revisions_count = max(1, len(eof_matches))

        # Check for /Sig flags or /ByteRange
        sig_matches = list(re.finditer(rb'/Type\s*/Sig\b', file_bytes))
        byterange_matches = list(re.finditer(rb'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', file_bytes))

        if sig_matches or byterange_matches:
            has_pdf_sig = True
            for m in byterange_matches:
                nums = [int(g) for g in m.groups()]
                byte_ranges.append(nums)
            
            if len(byte_ranges) > 0:
                sig_fields.append("Signature1 (PAdES / PKCS#7 adbe.pkcs7.detached)")
                # Check if file has data appended after the last ByteRange
                last_br = byte_ranges[-1]
                signed_length = last_br[2] + last_br[3]
                if len(file_bytes) > signed_length + 64:
                    changes_after_sig = "YES (Incremental modifications appended post-signing)"
                else:
                    changes_after_sig = "NO (Exact signed ByteRange covers document stream)"
            
            details = f"PAdES PDF Signature detected. Revisions: {revisions_count}. Signed ByteRanges: {len(byte_ranges)}."
    except Exception as e:
        details = f"PDF signature structure inspection completed with notice: {str(e)}"

    return {
        "pdf_signature_present": has_pdf_sig,
        "signature_fields": sig_fields,
        "byte_ranges": byte_ranges,
        "signed_revision": "Revision 1" if has_pdf_sig else "N/A",
        "current_revision": f"Revision {revisions_count}",
        "changes_after_signature": changes_after_sig,
        "details": details
    }

def extract_file_content(file_bytes: bytes, filename: str) -> dict:
    """
    Extracts text content, structured fields, and cryptographic markers safely.
    """
    ext = os.path.splitext(filename)[1].lower()
    raw_text = ""
    meta = {}
    structured_fields = {}
    status = "SUCCESS"
    warning = None

    try:
        if ext in ['.txt', '.log', '']:
            raw_text = file_bytes.decode('utf-8', errors='replace')
            meta['format'] = 'Plain Text'
            meta['character_count'] = len(raw_text)

        elif ext == '.json':
            decoded = file_bytes.decode('utf-8', errors='replace')
            raw_text = decoded
            try:
                parsed_json = json.loads(decoded)
                meta['format'] = 'JSON Structured Object'
                if isinstance(parsed_json, dict):
                    meta['keys_detected'] = list(parsed_json.keys())
                    # Semantic field extraction
                    for k, v in parsed_json.items():
                        k_norm = k.lower().replace('-', '_').replace(' ', '_')
                        structured_fields[k_norm] = str(v)
            except Exception as je:
                meta['format'] = 'Malformed JSON'
                warning = f"JSON parse note: {str(je)}"

        elif ext == '.csv':
            decoded = file_bytes.decode('utf-8', errors='replace')
            raw_text = decoded
            try:
                reader = csv.reader(io.StringIO(decoded))
                rows = list(reader)
                meta['format'] = 'CSV Data Table'
                meta['row_count'] = len(rows)
                if rows:
                    headers = [h.strip().lower().replace('-', '_') for h in rows[0]]
                    meta['columns'] = headers
                    if len(rows) > 1:
                        for idx, h in enumerate(headers):
                            if idx < len(rows[1]):
                                structured_fields[h] = rows[1][idx].strip()
            except Exception as ce:
                meta['format'] = 'CSV Format'
                warning = f"CSV read note: {str(ce)}"

        elif ext == '.pdf':
            meta['format'] = 'PDF Document'
            pdf_sig_info = inspect_pdf_signatures(file_bytes)
            meta['pdf_signatures'] = pdf_sig_info

            # Try pypdf text extraction if installed
            extracted_text = ""
            try:
                import pypdf
                pdf_reader = pypdf.PdfReader(io.BytesIO(file_bytes))
                meta['page_count'] = len(pdf_reader.pages)
                for page_idx, page in enumerate(pdf_reader.pages):
                    t = page.extract_text() or ""
                    extracted_text += f"\n--- Page {page_idx + 1} ---\n" + t
                raw_text = extracted_text.strip()
            except ImportError:
                # Safe printable string scanner
                strings = []
                for chunk in file_bytes.split(b'\n'):
                    try:
                        decoded_chunk = chunk.decode('latin1', errors='ignore')
                        cleaned = ''.join(c for c in decoded_chunk if 32 <= ord(c) <= 126 or c in '\r\n\t')
                        if len(cleaned) > 4:
                            strings.append(cleaned)
                    except Exception:
                        pass
                raw_text = "\n".join(strings[:200])
                meta['note'] = "Stream string scanner utilized for PDF text extraction."
            except Exception as pe:
                warning = f"PDF stream extraction notice: {str(pe)}"
                raw_text = file_bytes[:4096].decode('latin1', errors='ignore')

        elif ext in ['.p7s', '.p7m', '.der', '.crt', '.cer', '.pem', '.asc']:
            meta['format'] = f'Cryptographic Container ({ext.upper()})'
            try:
                raw_text = file_bytes.decode('utf-8', errors='ignore')
                if len(raw_text.strip()) < 10:
                    raw_text = f"BINARY CRYPTOGRAPHIC CONTAINER: {filename}\nSize: {len(file_bytes)} bytes\nSHA-256: {compute_sha256_bytes(file_bytes)}"
            except Exception:
                raw_text = f"BINARY CRYPTOGRAPHIC CONTAINER: {filename}\nSize: {len(file_bytes)} bytes\nSHA-256: {compute_sha256_bytes(file_bytes)}"

        else:
            raw_text = file_bytes.decode('utf-8', errors='replace')
            meta['format'] = f'Custom Format ({ext})'

    except Exception as e:
        status = "EXTRACTION_WARNING"
        warning = str(e)
        raw_text = file_bytes[:2048].decode('latin1', errors='ignore')

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]

    return {
        "raw_text": raw_text,
        "lines": lines,
        "line_count": len(lines),
        "extracted_type": ext if ext else ".txt",
        "structured_fields": structured_fields,
        "meta": meta,
        "status": status,
        "warning": warning
    }

def analyze_file_metadata(file_bytes: bytes, filename: str, reference_hash: Optional[str] = None) -> dict:
    """
    Computes file size, SHA-256 digest, MIME type, magic bytes, and integrity comparison.
    Adheres strictly to cryptographic integrity terminology.
    """
    file_size = len(file_bytes)
    sha256_hash = compute_sha256_bytes(file_bytes)
    ext = os.path.splitext(filename)[1].lower() or ".txt"
    upload_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    size_formatted = f"{file_size} bytes"
    if file_size > 1024 * 1024:
        size_formatted = f"{file_size / (1024*1024):.2f} MB"
    elif file_size > 1024:
        size_formatted = f"{file_size / 1024:.2f} KB"

    mime_info = detect_mime_and_magic(file_bytes, filename)
    content_info = extract_file_content(file_bytes, filename)

    # Correct Integrity Terminology (Phase 2)
    if reference_hash:
        ref_clean = reference_hash.strip().lower()
        if sha256_hash.lower() == ref_clean:
            integrity_comparison = "AVAILABLE"
            integrity_status = "VERIFIED (Matches Reference Digest)"
            hash_match = "YES"
        else:
            integrity_comparison = "AVAILABLE"
            integrity_status = "MISMATCH (Digest does not match Reference)"
            hash_match = "NO"
    else:
        integrity_comparison = "NOT AVAILABLE (No Reference Hash Supplied)"
        integrity_status = "UNVERIFIED (SHA-256 Calculated for Ingested Bytes)"
        hash_match = "N/A"

    return {
        "filename": filename,
        "file_type": ext.upper().replace(".", "") if ext else "TXT",
        "mime_type": mime_info["mime"],
        "magic_header": mime_info["magic"],
        "file_size": size_formatted,
        "file_size_bytes": file_size,
        "upload_time": upload_time,
        "sha256": sha256_hash,
        "sha256_computation": "SUCCESS",
        "reference_hash": reference_hash or "None provided",
        "hash_match": hash_match,
        "integrity_comparison": integrity_comparison,
        "integrity_status": integrity_status,
        "content_info": content_info
    }
