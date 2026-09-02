"""
Quantum Digital Signature Security Analyzer
Quantum-Inspired Engine (QDS & QKD Simulation Module)
Provides simulated quantum key distribution and quantum digital signature metrics.
Disclaimers:
  - "Quantum metrics are simulated for prototype demonstration."
  - "Quantum threat detection in this prototype is a simulated/quantum-inspired analysis and does not represent physical quantum hardware telemetry."
"""

import random
from typing import Dict, Any

def calculate_quantum_metrics(file_text: str, detected_threat: str, parsed_metrics: dict = None) -> Dict[str, Any]:
    """
    Computes quantum digital signature and channel telemetry.
    If the file content has embedded QBER/rounds/matches/mismatches, uses those exact parsed values.
    Otherwise derives realistic quantum-inspired baseline or threat-elevated values.
    """
    if parsed_metrics is None:
        parsed_metrics = {}

    is_quantum_threat = "Entangle" in detected_threat or "Quantum" in detected_threat
    is_attack = detected_threat not in ["None", "Normal"] and detected_threat != ""

    # Check for parsed values from file
    if 'qber' in parsed_metrics:
        qber = parsed_metrics['qber']
    elif is_quantum_threat:
        qber = 0.4700
    elif is_attack:
        qber = round(random.uniform(0.04, 0.08), 4)
    else:
        qber = round(random.uniform(0.008, 0.018), 4)

    # Rounds
    if 'rounds' in parsed_metrics:
        rounds = parsed_metrics['rounds']
    else:
        rounds = 100 if is_quantum_threat else 128

    # Mismatches & Matches
    if 'mismatches' in parsed_metrics and 'matches' in parsed_metrics:
        mismatches = parsed_metrics['mismatches']
        matches = parsed_metrics['matches']
    elif 'mismatch_rate' in parsed_metrics:
        mismatch_rate = parsed_metrics['mismatch_rate']
        mismatches = int(round(rounds * mismatch_rate))
        matches = rounds - mismatches
    else:
        mismatches = int(round(rounds * qber))
        matches = rounds - mismatches

    mismatch_rate = round(mismatches / max(1, rounds), 4)
    matching_rate = round(matches / max(1, rounds), 4)

    # Quantum risk and eavesdropping probability calculation
    # Theoretical QBER security threshold is ~11% (0.11) in BB84/QDS protocols
    qber_threshold = 0.11
    if qber >= qber_threshold:
        eavesdrop_prob = min(99.9, round(85.0 + (qber - qber_threshold) * 35.0, 2))
        quantum_risk = "CRITICAL"
        security_level = "POSSIBLE QUANTUM EAVESDROPPING (High QBER Detected)"
        assessment_note = "High QBER is consistent with possible quantum-channel disturbance during simulated photon transmission."
    elif qber >= 0.05:
        eavesdrop_prob = round(20.0 + (qber * 300), 2)
        quantum_risk = "MODERATE"
        security_level = "DEGRADED (Elevated Channel Noise)"
        assessment_note = "Elevated error rate observed; falls within acceptable noise threshold for standard fiber channels."
    else:
        eavesdrop_prob = round(qber * 40.0, 2)
        quantum_risk = "MINIMAL"
        security_level = "SECURE (Within Theoretical Bound)"
        assessment_note = "Error rate well below the 11.00% QDS security bound. State fidelity preserved."

    return {
        "qber": qber,
        "qber_percentage": f"{qber * 100:.2f}%",
        "mismatch_rate": mismatch_rate,
        "mismatch_rate_percentage": f"{mismatch_rate * 100:.2f}%",
        "matching_rate": matching_rate,
        "matching_rate_percentage": f"{matching_rate * 100:.2f}%",
        "quantum_risk": quantum_risk,
        "estimated_eavesdropping_probability": f"{eavesdrop_prob}%",
        "estimated_eavesdropping_probability_value": eavesdrop_prob,
        "security_level": security_level,
        "assessment_note": assessment_note,
        "number_of_rounds": rounds,
        "matches": matches,
        "mismatches": mismatches,
        "qber_threshold": "11.00%",
        "state_preservation_fidelity": f"{(1.0 - qber) * 100:.2f}%",
        "detection_mode": "SIMULATED / QUANTUM-INSPIRED",
        "disclaimer": "Quantum metrics are simulated for prototype demonstration. Quantum threat detection in this prototype is a simulated/quantum-inspired analysis and does not represent physical quantum hardware telemetry."
    }
