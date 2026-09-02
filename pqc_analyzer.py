"""
Quantum Digital Signature Security Analyzer
PQC Analyzer Module: Post-Quantum Cryptography Assessment, Crypto-Agility & CycloneDX CBOM Generator
Evaluates algorithms against NIST Post-Quantum Standards (FIPS 204 ML-DSA, FIPS 205 SLH-DSA, LMS, XMSS)
and generates a structured Cryptography Bill of Materials (CBOM).
"""

import re
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Knowledge Base of Cryptographic Algorithms & PQC Migration Attributes
ALGORITHM_PQC_CATALOG = {
    "RSA-1024": {
        "classical_security": "BROKEN / DEPRECATED",
        "quantum_security": "VULNERABLE (Broken via Shor's Algorithm)",
        "pqc_status": "NOT QUANTUM-SAFE",
        "nist_status": "Disallowed (NIST SP 800-131A)",
        "migration_priority": "CRITICAL",
        "recommended_pqc": "ML-DSA-65 (NIST FIPS 204)",
        "recommended_pqc_secondary": "SLH-DSA-128f (NIST FIPS 205)",
        "quantum_readiness_score": 10,
        "crypto_agility_score": 35,
        "description": "Short modulus RSA susceptible to classical factoring and completely broken by cryptographically relevant quantum computers (CRQC)."
    },
    "RSA-2048": {
        "classical_security": "ACCEPTABLE (112-bit security)",
        "quantum_security": "VULNERABLE to sufficiently capable cryptographically relevant quantum computers (CRQC)",
        "pqc_status": "NOT QUANTUM-SAFE",
        "nist_status": "Legacy use through 2030 (NIST SP 800-131A)",
        "migration_priority": "HIGH",
        "recommended_pqc": "ML-DSA-65 (NIST FIPS 204)",
        "recommended_pqc_secondary": "SLH-DSA-128s (NIST FIPS 205)",
        "quantum_readiness_score": 38,
        "crypto_agility_score": 52,
        "description": "Standard classical RSA. Vulnerable to polynomial-time quantum period-finding via Shor's algorithm."
    },
    "RSA-3072": {
        "classical_security": "STRONG (128-bit security)",
        "quantum_security": "VULNERABLE to sufficiently capable cryptographically relevant quantum computers (CRQC)",
        "pqc_status": "NOT QUANTUM-SAFE",
        "nist_status": "Acceptable classical until PQC migration deadline",
        "migration_priority": "MEDIUM-HIGH",
        "recommended_pqc": "ML-DSA-65 (NIST FIPS 204)",
        "recommended_pqc_secondary": "SLH-DSA-192s (NIST FIPS 205)",
        "quantum_readiness_score": 45,
        "crypto_agility_score": 58,
        "description": "128-bit classical strength; still entirely vulnerable to Shor's algorithm on quantum systems."
    },
    "RSA-4096": {
        "classical_security": "VERY STRONG (140-bit security)",
        "quantum_security": "VULNERABLE to sufficiently capable cryptographically relevant quantum computers (CRQC)",
        "pqc_status": "NOT QUANTUM-SAFE",
        "nist_status": "Acceptable classical",
        "migration_priority": "MEDIUM",
        "recommended_pqc": "ML-DSA-87 (NIST FIPS 204)",
        "recommended_pqc_secondary": "SLH-DSA-256s (NIST FIPS 205)",
        "quantum_readiness_score": 50,
        "crypto_agility_score": 60,
        "description": "High classical complexity, but large key size causes performance bottlenecks and offers no quantum immunity."
    },
    "ECDSA": {
        "classical_security": "STRONG (128-bit elliptic curve)",
        "quantum_security": "VULNERABLE to sufficiently capable cryptographically relevant quantum computers (CRQC)",
        "pqc_status": "NOT QUANTUM-SAFE",
        "nist_status": "Current standard (FIPS 186-5), planned deprecation post-2030",
        "migration_priority": "HIGH",
        "recommended_pqc": "ML-DSA-65 (NIST FIPS 204)",
        "recommended_pqc_secondary": "SLH-DSA-128f (NIST FIPS 205)",
        "quantum_readiness_score": 42,
        "crypto_agility_score": 65,
        "description": "Elliptic curve discrete logarithm problem is efficiently solvable via Shor's algorithm on quantum hardware."
    },
    "ECDSA-P256-SHA256": {
        "classical_security": "STRONG (128-bit elliptic curve)",
        "quantum_security": "VULNERABLE to sufficiently capable cryptographically relevant quantum computers (CRQC)",
        "pqc_status": "NOT QUANTUM-SAFE",
        "nist_status": "FIPS 186-5 ECDSA",
        "migration_priority": "HIGH",
        "recommended_pqc": "ML-DSA-65 (NIST FIPS 204)",
        "recommended_pqc_secondary": "SLH-DSA-128f (NIST FIPS 205)",
        "quantum_readiness_score": 44,
        "crypto_agility_score": 68,
        "description": "Widely deployed standard. High crypto-agility facilitates drop-in replacement with lattice-based ML-DSA."
    },
    "Ed25519": {
        "classical_security": "VERY STRONG (128-bit Edwards curve)",
        "quantum_security": "VULNERABLE to sufficiently capable cryptographically relevant quantum computers (CRQC)",
        "pqc_status": "NOT QUANTUM-SAFE",
        "nist_status": "FIPS 186-5 Approved",
        "migration_priority": "HIGH",
        "recommended_pqc": "ML-DSA-65 (NIST FIPS 204)",
        "recommended_pqc_secondary": "SLH-DSA-128f (NIST FIPS 205)",
        "quantum_readiness_score": 48,
        "crypto_agility_score": 72,
        "description": "High performance modern curve; vulnerable to quantum discrete logarithm computation."
    },
    "ML-DSA": {
        "classical_security": "QUANTUM-RESISTANT (NIST Level 2/3/5)",
        "quantum_security": "QUANTUM-SAFE (Module-Lattice Based)",
        "pqc_status": "POST-QUANTUM STANDARD",
        "nist_status": "NIST FIPS 204 Standardized (August 2024)",
        "migration_priority": "COMPLETED / ADOPTED",
        "recommended_pqc": "ML-DSA-65 (Active Native Standard)",
        "recommended_pqc_secondary": "Hybrid ML-DSA + ECDSA",
        "quantum_readiness_score": 98,
        "crypto_agility_score": 95,
        "description": "Primary NIST post-quantum digital signature standard based on Module Learning with Errors (M-LWE)."
    },
    "SLH-DSA": {
        "classical_security": "QUANTUM-RESISTANT (NIST Level 1/3/5)",
        "quantum_security": "QUANTUM-SAFE (Stateless Hash-Based)",
        "pqc_status": "POST-QUANTUM STANDARD",
        "nist_status": "NIST FIPS 205 Standardized (August 2024)",
        "migration_priority": "COMPLETED / ADOPTED",
        "recommended_pqc": "SLH-DSA-128f (Active Native Standard)",
        "recommended_pqc_secondary": "SLH-DSA-128s",
        "quantum_readiness_score": 96,
        "crypto_agility_score": 92,
        "description": "Stateless hash-based signature scheme relying solely on cryptographic hash security (no lattice assumptions)."
    },
    "LMS": {
        "classical_security": "QUANTUM-RESISTANT",
        "quantum_security": "QUANTUM-SAFE (Stateful Hash-Based)",
        "pqc_status": "POST-QUANTUM APPROVED (Stateful)",
        "nist_status": "NIST SP 800-208 / RFC 8554 (Firmware & Boot Only)",
        "migration_priority": "SPECIALIZED ADOPTION",
        "recommended_pqc": "Leighton-Micali Signatures (LMS)",
        "recommended_pqc_secondary": "XMSS",
        "quantum_readiness_score": 88,
        "crypto_agility_score": 78,
        "description": "Stateful hash-based signature intended strictly for code signing and firmware validation."
    }
}

def analyze_post_quantum_posture(detected_algo: str, raw_text: str = "") -> Dict[str, Any]:
    """
    Evaluates Post-Quantum Readiness and Crypto-Agility for detected digital signature algorithms.
    """
    # Normalize algorithm key
    matched_key = "ECDSA-P256-SHA256"
    for k in ALGORITHM_PQC_CATALOG.keys():
        if re.search(rf'\b{re.escape(k)}\b', detected_algo, re.IGNORECASE) or re.search(rf'\b{re.escape(k)}\b', raw_text, re.IGNORECASE):
            matched_key = k
            break

    profile = ALGORITHM_PQC_CATALOG.get(matched_key, ALGORITHM_PQC_CATALOG["ECDSA-P256-SHA256"])

    # Readiness & Agility factors
    readiness_score = profile["quantum_readiness_score"]
    agility_score = profile["crypto_agility_score"]

    # If already PQC standard
    is_pqc_native = "POST-QUANTUM" in profile["pqc_status"]
    
    if is_pqc_native:
        agility_narrative = (
            f"The architecture utilizes {matched_key}, which is standardized under {profile['nist_status']}. "
            "Crypto-agility is high with direct compatibility for post-quantum PKI certificates."
        )
    else:
        agility_narrative = (
            f"The detected algorithm {matched_key} relies on classical mathematical hardness that is "
            f"{profile['quantum_security']}. Migration to {profile['recommended_pqc']} is recommended to achieve quantum resilience."
        )

    return {
        "detected_algorithm": matched_key,
        "classical_security": profile["classical_security"],
        "quantum_security": profile["quantum_security"],
        "pqc_status": profile["pqc_status"],
        "nist_standard": profile["nist_status"],
        "migration_priority": profile["migration_priority"],
        "recommended_pqc": profile["recommended_pqc"],
        "recommended_pqc_secondary": profile["recommended_pqc_secondary"],
        "pqc_readiness_score": readiness_score,
        "crypto_agility_score": agility_score,
        "technical_assessment": profile["description"],
        "crypto_agility_rationale": agility_narrative,
        "is_quantum_safe": is_pqc_native,
        "assessment_label": "Prototype Readiness Assessment (NIST FIPS 204/205 Baseline)"
    }

def generate_cbom_json(
    file_meta: Dict[str, Any],
    sig_info: Dict[str, Any],
    pqc_info: Dict[str, Any],
    cert_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generates a structured CycloneDX-inspired Cryptography Bill of Materials (CBOM).
    """
    bom_uuid = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    algo_name = pqc_info.get("detected_algorithm", "ECDSA")
    is_safe = pqc_info.get("is_quantum_safe", False)
    
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": bom_uuid,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Quantum Digital Signature Security Analyzer",
                    "name": "QDS-CBOM-Engine",
                    "version": "2.4.0-PQC"
                }
            ],
            "component": {
                "type": "cryptographic-asset",
                "name": file_meta.get("filename", "signature_payload.txt"),
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": file_meta.get("sha256", "")
                    }
                ]
            }
        },
        "declarations": {
            "standards": [
                {"name": "NIST FIPS 186-5", "description": "Digital Signature Standard"},
                {"name": "NIST FIPS 204", "description": "Module-Lattice-Based Digital Signature Standard (ML-DSA)"},
                {"name": "NIST FIPS 205", "description": "Stateless Hash-Based Digital Signature Standard (SLH-DSA)"}
            ]
        },
        "cryptoProperties": {
            "assetType": "digital-signature-bundle",
            "algorithms": [
                {
                    "name": algo_name,
                    "primitive": "signature",
                    "classicalSecurityBits": 128 if "256" in algo_name or "ECDSA" in algo_name else (112 if "2048" in algo_name else 256),
                    "quantumSecurityLevel": "QUANTUM-RESISTANT" if is_safe else "VULNERABLE",
                    "nistCategory": pqc_info.get("nist_standard", "FIPS 186-5"),
                    "pqcStatus": pqc_info.get("pqc_status", "NOT QUANTUM-SAFE")
                },
                {
                    "name": "SHA-256",
                    "primitive": "hash",
                    "classicalSecurityBits": 256,
                    "quantumSecurityLevel": "QUANTUM-RESISTANT (Grover 128-bit collision resistance)",
                    "nistCategory": "FIPS 180-4"
                }
            ],
            "certificates": [
                {
                    "subject": cert_info.get("subject", "N/A"),
                    "issuer": cert_info.get("issuer", "N/A"),
                    "serialNumber": cert_info.get("serial_number", "N/A"),
                    "fingerprintSha256": cert_info.get("fingerprint_sha256", "N/A"),
                    "trustStatus": cert_info.get("trust_chain", "UNAVAILABLE")
                }
            ],
            "migrationStrategy": {
                "priority": pqc_info.get("migration_priority", "HIGH"),
                "targetPqcAlgorithm": pqc_info.get("recommended_pqc", "ML-DSA-65"),
                "readinessScore": pqc_info.get("pqc_readiness_score", 42),
                "agilityScore": pqc_info.get("crypto_agility_score", 58)
            }
        }
    }
    
    return cbom
