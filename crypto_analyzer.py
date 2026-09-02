"""
Quantum-Inspired Cyber Threat Detection for Digital Signature Security
Module: Crypto Analyzer
Mathematical verification, SHA-256 calculation, and public-key rule verification.
"""

from file_analyzer import compute_sha256_bytes, analyze_file_metadata
from crypto_verifier import verify_cryptographic_payload, get_or_generate_demo_keys
from certificate_analyzer import analyze_certificate_data

def analyze_crypto_security(file_bytes: bytes, filename: str, reference_hash: str = None):
    """Executes pure mathematical cryptographic digest and public key verification."""
    sha256_hash = compute_sha256_bytes(file_bytes)
    meta = analyze_file_metadata(file_bytes, filename, reference_hash)
    crypto_verif = verify_cryptographic_payload(file_bytes, filename, meta['content_info']['raw_text'])
    cert_info = analyze_certificate_data(file_bytes, filename, meta['content_info']['raw_text'])
    
    return {
        "sha256": sha256_hash,
        "metadata": meta,
        "crypto_verification": crypto_verif,
        "certificate_info": cert_info
    }
