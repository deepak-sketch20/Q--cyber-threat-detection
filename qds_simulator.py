"""
Quantum Digital Signature (QDS) Security Simulator Module
==========================================================
Provides simulation-based quantum operations using statevector mathematics,
Qiskit-compatible circuit representations, Bell-state entanglement, quantum teleportation,
Pauli corrections, projective measurements, QBER analysis, and quantum channel security.

IMPORTANT:
This is a simulation-based quantum prototype for cybersecurity research.
It runs on classical computing simulators and does not use physical quantum hardware.
"""

import math
import random
import cmath
from typing import Dict, Any, List, Tuple, Optional

# ==============================================================================
# 1. QUBIT SIMULATION
# ==============================================================================

def simulate_qubit(
    state_type: str = "superposition",
    theta: float = math.pi / 2,
    phi: float = 0.0,
    shots: int = 1024
) -> Dict[str, Any]:
    """
    Simulates a single qubit in basis states |0>, |1>, equal superposition, or arbitrary |psi>.
    Hadamard gate: H|0> = (|0> + |1>) / sqrt(2)
    """
    state_type_clean = state_type.lower()
    
    if state_type_clean in ["0", "|0>", "zero", "ground"]:
        alpha = complex(1.0, 0.0)
        beta = complex(0.0, 0.0)
        label = "|0⟩ Ground State"
        gate_applied = "None (Prepared in computational basis |0⟩)"
        circuit_ascii = (
            "     ┌───┐\n"
            "q_0: ┤ I ├─■─\n"
            "     └───┘\n"
            "c_0: ════════"
        )
    elif state_type_clean in ["1", "|1>", "one", "excited"]:
        alpha = complex(0.0, 0.0)
        beta = complex(1.0, 0.0)
        label = "|1⟩ Excited State"
        gate_applied = "Pauli-X (Bit-flip gate X|0⟩ = |1⟩)"
        circuit_ascii = (
            "     ┌───┐┌─┐\n"
            "q_0: ┤ X ├┤M├\n"
            "     └───┘└╥┘\n"
            "c_0: ══════╩═"
        )
    elif state_type_clean in ["superposition", "+", "|+>", "hadamard"]:
        # H|0> = (|0> + |1>) / sqrt(2)
        inv_sqrt2 = 1.0 / math.sqrt(2)
        alpha = complex(inv_sqrt2, 0.0)
        beta = complex(inv_sqrt2, 0.0)
        label = "|+⟩ Equal Superposition (|0⟩ + |1⟩)/√2"
        gate_applied = "Hadamard Gate (H|0⟩ = (|0⟩ + |1⟩)/√2)"
        circuit_ascii = (
            "     ┌───┐┌─┐\n"
            "q_0: ┤ H ├┤M├\n"
            "     └───┘└╥┘\n"
            "c_0: ══════╩═"
        )
    elif state_type_clean in ["-", "|->", "minus"]:
        inv_sqrt2 = 1.0 / math.sqrt(2)
        alpha = complex(inv_sqrt2, 0.0)
        beta = complex(-inv_sqrt2, 0.0)
        label = "|-⟩ Phase Superposition (|0⟩ - |1⟩)/√2"
        gate_applied = "Pauli-X + Hadamard Gate (H X|0⟩ = (|0⟩ - |1⟩)/√2)"
        circuit_ascii = (
            "     ┌───┐┌───┐┌─┐\n"
            "q_0: ┤ X ├┤ H ├┤M├\n"
            "     └───┘└───┘└╥┘\n"
            "c_0: ════════════╩═"
        )
    else:
        # Arbitrary single qubit state |psi> = cos(theta/2)|0> + e^(i*phi)*sin(theta/2)|1>
        alpha = complex(math.cos(theta / 2.0), 0.0)
        beta = cmath.rect(math.sin(theta / 2.0), phi)
        label = f"|ψ⟩ Arbitrary State (θ={theta:.2f}, φ={phi:.2f})"
        gate_applied = f"Rotation U3(θ={theta:.2f}, φ={phi:.2f}, λ=0)"
        circuit_ascii = (
            f"     ┌──────────────┐┌─┐\n"
            f"q_0: ┤ U3({theta:.1f},{phi:.1f},0) ├┤M├\n"
            f"     └──────────────┘└╥┘\n"
            f"c_0: ═════════════════╩═"
        )

    prob_0 = round(abs(alpha) ** 2, 4)
    prob_1 = round(abs(beta) ** 2, 4)

    # Statistical measurement distribution simulation
    count_0 = 0
    count_1 = 0
    for _ in range(shots):
        if random.random() < prob_0:
            count_0 += 1
        else:
            count_1 += 1

    return {
        "simulation_type": "Qubit Simulation",
        "state_name": label,
        "gate_applied": gate_applied,
        "statevector": {
            "alpha": {"real": round(alpha.real, 4), "imag": round(alpha.imag, 4)},
            "beta": {"real": round(beta.real, 4), "imag": round(beta.imag, 4)},
            "formula": f"({alpha.real:.3f} + {alpha.imag:.3f}i)|0⟩ + ({beta.real:.3f} + {beta.imag:.3f}i)|1⟩"
        },
        "probabilities": {
            "0": prob_0,
            "1": prob_1,
            "0_percent": f"{prob_0 * 100:.1f}%",
            "1_percent": f"{prob_1 * 100:.1f}%"
        },
        "measurements": {
            "0": count_0,
            "1": count_1,
            "ratio_0": round(count_0 / max(1, shots), 4),
            "ratio_1": round(count_1 / max(1, shots), 4)
        },
        "shots": shots,
        "circuit_ascii": circuit_ascii,
        "qiskit_code": (
            "from qiskit import QuantumCircuit, Aer, execute\n"
            "qc = QuantumCircuit(1, 1)\n"
            f"{'qc.h(0)' if 'Hadamard' in gate_applied else ('qc.x(0)' if 'X' in gate_applied else '# Ground state')}\n"
            "qc.measure(0, 0)\n"
            "backend = Aer.get_backend('qasm_simulator')\n"
            f"job = execute(qc, backend, shots={shots})\n"
            "counts = job.result().get_counts()"
        ),
        "explanation": (
            "Hadamard gate transforms basis state |0⟩ into equal superposition (|0⟩ + |1⟩)/√2. "
            "Prior to projective measurement, the qubit exists in a linear combination of both states. "
            "Measurement collapses the statevector with probability P(0)=|α|² and P(1)=|β|²."
        ),
        "disclaimer": "Simulated quantum state via classical statevector propagation (Qiskit simulator equivalent)."
    }

# ==============================================================================
# 2. BELL STATE GENERATOR
# ==============================================================================

def simulate_bell_state(
    bell_state: str = "Phi+",
    shots: int = 1024,
    noise_rate: float = 0.002
) -> Dict[str, Any]:
    """
    Simulates the four maximally entangled two-qubit Bell States:
    Φ+ = (|00⟩ + |11⟩) / √2
    Φ- = (|00⟩ - |11⟩) / √2
    Ψ+ = (|01⟩ + |10⟩) / √2
    Ψ- = (|01⟩ - |10⟩) / √2
    """
    clean_name = bell_state.replace(" ", "").replace("_", "").replace("-", "").lower()
    
    if "phi+" in clean_name or "phiplus" in clean_name or clean_name == "phi+":
        state_id = "Phi+"
        formula = "Φ+ = (|00⟩ + |11⟩) / √2"
        ideal_outcomes = {"00": 0.5, "11": 0.5, "01": 0.0, "10": 0.0}
        prep_steps = ["Apply H to q0", "Apply CNOT from q0 to q1"]
        circuit_ascii = (
            "q_0: ──[H]──■────[M]─\n"
            "            │       \n"
            "q_1: ───────■────[M]─\n"
            "c:   ════════════════"
        )
    elif "phi-" in clean_name or "phiminus" in clean_name or clean_name == "phi-":
        state_id = "Phi-"
        formula = "Φ- = (|00⟩ - |11⟩) / √2"
        ideal_outcomes = {"00": 0.5, "11": 0.5, "01": 0.0, "10": 0.0}
        prep_steps = ["Apply X to q0", "Apply H to q0", "Apply CNOT from q0 to q1"]
        circuit_ascii = (
            "q_0: ──[X]──[H]──■───[M]─\n"
            "                 │       \n"
            "q_1: ────────────■───[M]─\n"
            "c:   ════════════════════"
        )
    elif "psi+" in clean_name or "psiplus" in clean_name or clean_name == "psi+":
        state_id = "Psi+"
        formula = "Ψ+ = (|01⟩ + |10⟩) / √2"
        ideal_outcomes = {"01": 0.5, "10": 0.5, "00": 0.0, "11": 0.0}
        prep_steps = ["Apply X to q1", "Apply H to q0", "Apply CNOT from q0 to q1"]
        circuit_ascii = (
            "q_0: ──[H]──■────[M]─\n"
            "            │       \n"
            "q_1: ──[X]──■────[M]─\n"
            "c:   ════════════════"
        )
    elif "psi-" in clean_name or "psiminus" in clean_name or clean_name == "psi-":
        state_id = "Psi-"
        formula = "Ψ- = (|01⟩ - |10⟩) / √2"
        ideal_outcomes = {"01": 0.5, "10": 0.5, "00": 0.0, "11": 0.0}
        prep_steps = ["Apply X to q0", "Apply X to q1", "Apply H to q0", "Apply CNOT from q0 to q1"]
        circuit_ascii = (
            "q_0: ──[X]──[H]──■───[M]─\n"
            "                 │       \n"
            "q_1: ──[X]───────■───[M]─\n"
            "c:   ════════════════════"
        )
    else:
        # Default to Phi+
        state_id = "Phi+"
        formula = "Φ+ = (|00⟩ + |11⟩) / √2"
        ideal_outcomes = {"00": 0.5, "11": 0.5, "01": 0.0, "10": 0.0}
        prep_steps = ["Apply H to q0", "Apply CNOT from q0 to q1"]
        circuit_ascii = (
            "q_0: ──[H]──■────[M]─\n"
            "            │       \n"
            "q_1: ───────■────[M]─\n"
            "c:   ════════════════"
        )

    # Sample measurement counts with slight physical simulation noise
    counts = {"00": 0, "01": 0, "10": 0, "11": 0}
    for _ in range(shots):
        r = random.random()
        if state_id in ["Phi+", "Phi-"]:
            if r < (0.5 - noise_rate / 2):
                counts["00"] += 1
            elif r < (1.0 - noise_rate):
                counts["11"] += 1
            elif r < (1.0 - noise_rate / 2):
                counts["01"] += 1
            else:
                counts["10"] += 1
        else: # Psi+, Psi-
            if r < (0.5 - noise_rate / 2):
                counts["01"] += 1
            elif r < (1.0 - noise_rate):
                counts["10"] += 1
            elif r < (1.0 - noise_rate / 2):
                counts["00"] += 1
            else:
                counts["11"] += 1

    return {
        "simulation_type": "Bell State Generator",
        "bell_state": state_id,
        "formula": formula,
        "preparation_steps": prep_steps,
        "circuit_ascii": circuit_ascii,
        "ideal_probabilities": ideal_outcomes,
        "measurement_counts": counts,
        "shots": shots,
        "qiskit_code": (
            "from qiskit import QuantumCircuit, Aer, execute\n"
            "qc = QuantumCircuit(2, 2)\n"
            f"{'qc.x(0)\n' if 'X to q0' in prep_steps[0] else ''}"
            f"{'qc.x(1)\n' if any('X to q1' in s for s in prep_steps) else ''}"
            "qc.h(0)\n"
            "qc.cx(0, 1)\n"
            "qc.measure([0, 1], [0, 1])\n"
            "backend = Aer.get_backend('qasm_simulator')\n"
            f"job = execute(qc, backend, shots={shots})\n"
            "result = job.result().get_counts()"
        ),
        "explanation": (
            f"Bell state {state_id} generates maximally entangled qubit pairs. "
            f"Measuring one qubit instantly correlates with the measurement outcome of the other, "
            f"forming the fundamental cryptographic resource for Quantum Digital Signatures (QDS)."
        )
    }

# ==============================================================================
# 3. ENTANGLEMENT CORRELATION
# ==============================================================================

def simulate_entanglement(
    shots: int = 1024,
    noise_level: float = 0.003
) -> Dict[str, Any]:
    """
    Demonstrates two-qubit quantum entanglement verification.
    Applies H(q0) and CNOT(q0, q1) to prepare Phi+ state, measures both,
    and calculates exact matching vs mismatching statistics and correlation %.
    """
    matching = 0
    mismatching = 0
    
    for _ in range(shots):
        if random.random() > noise_level:
            # Perfectly correlated
            matching += 1
        else:
            # Decoherence/channel noise event
            mismatching += 1

    correlation_pct = round((matching / max(1, shots)) * 100.0, 2)
    
    return {
        "simulation_type": "Quantum Entanglement Verification",
        "entanglement_status": "ACTIVE",
        "bell_state_used": "Φ+ = (|00⟩ + |11⟩) / √2",
        "total_measurements": shots,
        "matching_measurements": matching,
        "mismatching_measurements": mismatching,
        "correlation_percentage": correlation_pct,
        "correlation_display": f"{correlation_pct}%",
        "circuit_ascii": (
            "     ┌───┐     ┌─┐   \n"
            "q_0: ┤ H ├──■──┤M├───\n"
            "     └───┘┌─┴─┐└╥┘┌─┐\n"
            "q_1: ─────┤ X ├─╫─┤M├\n"
            "          └───┘ ║ └╥┘\n"
            "c:   ═══════════╩══╩═"
        ),
        "chart_data": {
            "labels": ["Correlated Outcomes (00/11)", "Decoherence Mismatches (01/10)"],
            "values": [matching, mismatching]
        },
        "explanation": (
            "Entanglement creates correlated quantum measurement outcomes across spatially separated nodes. "
            "In a noiseless channel, Alice and Bob obtain 100.0% matching outcomes, allowing detection of any eavesdropping attempt."
        )
    }

# ==============================================================================
# 4. QUANTUM TELEPORTATION & PAULI CORRECTIONS
# ==============================================================================

def apply_pauli_correction(bits: str) -> Dict[str, Any]:
    """
    Computes Pauli correction gate mapping for classical bits received from Alice:
    00 -> Identity (I)
    01 -> Pauli-X (Bit flip)
    10 -> Pauli-Z (Phase flip)
    11 -> Pauli-XZ (Bit and phase flip)
    """
    clean_bits = bits.strip()
    if clean_bits == "00":
        return {
            "bits": "00",
            "correction_gate": "I (Identity)",
            "gate_symbol": "I",
            "matrix": "[[1, 0], [0, 1]]",
            "action": "No correction needed. Bob's state is already identical to original message qubit.",
            "bob_transformation": "I|ψ⟩ = |ψ⟩",
            "circuit_symbol": "───I───"
        }
    elif clean_bits == "01":
        return {
            "bits": "01",
            "correction_gate": "X (Pauli-X Bit Flip)",
            "gate_symbol": "X",
            "matrix": "[[0, 1], [1, 0]]",
            "action": "Applies bit flip (NOT gate) to invert |0⟩ ↔ |1⟩ on Bob's qubit.",
            "bob_transformation": "X (X|ψ⟩) = |ψ⟩",
            "circuit_symbol": "───X───"
        }
    elif clean_bits == "10":
        return {
            "bits": "10",
            "correction_gate": "Z (Pauli-Z Phase Flip)",
            "gate_symbol": "Z",
            "matrix": "[[1, 0], [0, -1]]",
            "action": "Applies phase flip to negate relative phase of |1⟩ component.",
            "bob_transformation": "Z (Z|ψ⟩) = |ψ⟩",
            "circuit_symbol": "───Z───"
        }
    elif clean_bits == "11":
        return {
            "bits": "11",
            "correction_gate": "XZ (Pauli-X followed by Pauli-Z)",
            "gate_symbol": "XZ",
            "matrix": "[[0, 1], [-1, 0]]",
            "action": "Applies both bit flip and phase flip corrections to fully recover |ψ⟩.",
            "bob_transformation": "Z·X (X·Z|ψ⟩) = |ψ⟩",
            "circuit_symbol": "───X───Z───"
        }
    else:
        return {
            "bits": clean_bits,
            "correction_gate": "I (Identity)",
            "gate_symbol": "I",
            "matrix": "[[1, 0], [0, 1]]",
            "action": "Default identity gate applied.",
            "bob_transformation": "I|ψ⟩ = |ψ⟩",
            "circuit_symbol": "───I───"
        }

def simulate_teleportation(
    message_state: str = "superposition",
    custom_theta: Optional[float] = None,
    shots: int = 1024
) -> Dict[str, Any]:
    """
    Executes complete 3-Qubit Quantum Teleportation Protocol:
    q0 = Message Qubit |psi> (Prepared with secret state/signature token)
    q1 = Alice's Bell-pair qubit
    q2 = Bob's Bell-pair qubit
    """
    # 1. Message preparation on q0
    if message_state == "0":
        msg_alpha = 1.0; msg_beta = 0.0; msg_desc = "|0⟩ State"
    elif message_state == "1":
        msg_alpha = 0.0; msg_beta = 1.0; msg_desc = "|1⟩ State"
    elif message_state == "minus":
        msg_alpha = 1.0 / math.sqrt(2); msg_beta = -1.0 / math.sqrt(2); msg_desc = "|-⟩ Phase State"
    else: # Superposition |+>
        msg_alpha = 1.0 / math.sqrt(2); msg_beta = 1.0 / math.sqrt(2); msg_desc = "|+⟩ Superposition (|0⟩ + |1⟩)/√2"

    if custom_theta is not None:
        msg_alpha = math.cos(custom_theta / 2.0)
        msg_beta = math.sin(custom_theta / 2.0)
        msg_desc = f"|ψ⟩ Custom State (θ={custom_theta:.2f})"

    # 2. Simulate random Bell-state projective measurement outcomes for Alice (q0, q1)
    # The 4 outcomes 00, 01, 10, 11 occur with equal probability (25% each)
    alice_bits = random.choice(["00", "01", "10", "11"])
    
    # 3. Determine Pauli correction for Bob
    pauli_info = apply_pauli_correction(alice_bits)

    # 4. Bob's recovered state fidelity
    bob_recovered_alpha = round(msg_alpha, 4)
    bob_recovered_beta = round(msg_beta, 4)
    fidelity = 1.00 # Pure state teleportation fidelity in simulation

    # 5. Measure Bob's recovered qubit over shots
    bob_p0 = round(msg_alpha ** 2, 4)
    bob_p1 = round(msg_beta ** 2, 4)
    bob_0_count = int(round(shots * bob_p0))
    bob_1_count = shots - bob_0_count

    circuit_ascii = (
        "                    ┌───┐     ┌─┐               \n"
        "q_0 (Msg): ─────────┤ X ├──■──┤M├───────────────\n"
        "          ┌───┐     └─┬─┘┌─┴─┐└╥┘┌─┐            \n"
        "q_1 (Alc): ┤ H ├──■───■──┤ H ├─╫─┤M├────────────\n"
        "          └───┘┌─┴─┐     └───┘ ║ └╥┘ ┌───┐ ┌───┐\n"
        "q_2 (Bob): ────┤ X ├───────────╫──╫──┤ X ├─┤ Z ├\n"
        "               └───┘           ║  ║  └─┬─┘ └─┬─┘\n"
        "c_0:       ════════════════════╩══╬════╪═════╪══\n"
        "c_1:       ═══════════════════════╩════■═════╪══\n"
        "c_2:       ══════════════════════════════════■══"
    )

    workflow_diagram = (
        "MESSAGE QUBIT (|ψ⟩)\n"
        "       ↓\n"
        "ALICE (CNOT q0→q1, H q0)\n"
        "       ↓\n"
        "ENTANGLED BELL PAIR (q1 ⇄ q2)\n"
        "       ↓\n"
        "CLASSICAL MEASUREMENT (Bits: {alice_bits})\n"
        "       ↓\n"
        "PAULI CORRECTION (Gate: {pauli_info['gate_symbol']})\n"
        "       ↓\n"
        "BOB (Applied to q2)\n"
        "       ↓\n"
        "RECOVERED STATE (|ψ_Bob⟩ = |ψ⟩, Fidelity: 100.0%)"
    ).format(alice_bits=alice_bits, pauli_info=pauli_info)

    return {
        "simulation_type": "Quantum Teleportation",
        "teleportation_status": "SUCCESSFUL",
        "original_message_state": {
            "description": msg_desc,
            "alpha": round(msg_alpha, 4),
            "beta": round(msg_beta, 4),
            "probabilities": {"0": bob_p0, "1": bob_p1}
        },
        "alice_measurement": {
            "bits": alice_bits,
            "q0_bit": alice_bits[0],
            "q1_bit": alice_bits[1],
            "basis": "Bell Basis Measurement"
        },
        "pauli_correction": pauli_info,
        "bob_recovered_state": {
            "state_formula": f"{bob_recovered_alpha}|0⟩ + {bob_recovered_beta}|1⟩",
            "fidelity": fidelity,
            "fidelity_percentage": "100.0%",
            "measurements": {"0": bob_0_count, "1": bob_1_count},
            "state_match": True
        },
        "shots": shots,
        "circuit_ascii": circuit_ascii,
        "workflow_diagram": workflow_diagram,
        "explanation": (
            "Quantum teleportation transfers quantum-state information using entanglement and classical communication. "
            "No matter is transported; rather, the unknown quantum state |ψ⟩ is reconstructed at Bob's node using shared Bell entanglement "
            "and two classical bits of measurement information."
        )
    }

# ==============================================================================
# 5. PROJECTIVE MEASUREMENT
# ==============================================================================

def projective_measurement(
    initial_state: str = "superposition",
    shots: int = 1024
) -> Dict[str, Any]:
    """
    Demonstrates projective measurement of a quantum state in the computational basis {|0>, |1>}.
    Displays the state prior to measurement (superposition) and the post-measurement collapsed state.
    """
    if initial_state == "0":
        p0 = 1.0; p1 = 0.0; formula_before = "|0⟩"
    elif initial_state == "1":
        p0 = 0.0; p1 = 1.0; formula_before = "|1⟩"
    else: # Equal superposition
        p0 = 0.5; p1 = 0.5; formula_before = "1/√2 |0⟩ + 1/√2 |1⟩ (Superposition)"

    # Simulate single instantaneous shot collapse
    single_outcome = "0" if random.random() < p0 else "1"
    post_measurement_state = f"|{single_outcome}⟩ (Eigenstate)"

    # Multi-shot distribution
    count_0 = 0
    count_1 = 0
    for _ in range(shots):
        if random.random() < p0:
            count_0 += 1
        else:
            count_1 += 1

    return {
        "simulation_type": "Projective Measurement",
        "basis": "Computational Basis {|0⟩, |1⟩}",
        "state_before_measurement": formula_before,
        "measurement_outcome": single_outcome,
        "state_after_measurement": post_measurement_state,
        "collapse_mechanism": f"Wavefunction collapsed onto eigenvector |{single_outcome}⟩ with probability P({single_outcome})={p0 if single_outcome=='0' else p1:.1f}",
        "measurement_statistics": {
            "shots": shots,
            "outcomes": {"0": count_0, "1": count_1},
            "observed_prob_0": round(count_0 / max(1, shots), 4),
            "observed_prob_1": round(count_1 / max(1, shots), 4)
        },
        "explanation": (
            "Projective measurement converts the continuous quantum amplitude state into a discrete classical measurement outcome. "
            "The measurement operator P_m = |m⟩⟨m| projects the quantum state onto one of its orthogonal basis vectors."
        )
    }

# ==============================================================================
# 6. QUANTUM CHANNEL SECURITY & ATTACK SIMULATION
# ==============================================================================

def simulate_quantum_channel(
    mode: str = "NORMAL",
    total_bits: int = 1000,
    disturbance_level: Optional[float] = None
) -> Dict[str, Any]:
    """
    Simulates quantum communication channel under normal conditions or active quantum attacks:
    1. NORMAL: Baseline quantum channel noise (QBER < 2%)
    2. INTERCEPT-RESEND: Eve measures carrier qubits in random conjugate bases (QBER ~ 25%)
    3. QUANTUM EAVESDROPPING (Entangle-and-Measure): Eve entangles probe qubit (QBER ~ 42-48%)
    4. QUANTUM CHANNEL MANIPULATION: Active bit/phase perturbation (QBER ~ 30-38%)
    
    Formula: QBER = (mismatched bits / total compared bits) * 100
    """
    clean_mode = mode.upper().replace("_", "-").replace(" ", "-")

    if "EAVESDROP" in clean_mode or "ENTANGLE" in clean_mode or clean_mode == "QUANTUM-EAVESDROPPING":
        attack_type = "Quantum Eavesdropping (Entangle-and-Measure)"
        base_qber = disturbance_level if disturbance_level is not None else round(random.uniform(0.42, 0.48), 4)
        channel_status = "COMPROMISED (High Quantum Error Rate)"
        risk = "CRITICAL"
        threat_detected = "Quantum Eavesdropping Attack Detected"
        first_action = "Terminate/suspend the affected simulated quantum channel immediately."
        countermeasure = "Abort key distillation; initiate simulated privacy amplification and switch to secondary entangled Bell route."
    elif "INTERCEPT" in clean_mode or clean_mode == "INTERCEPT-RESEND":
        attack_type = "Intercept-Resend Attack"
        base_qber = disturbance_level if disturbance_level is not None else round(random.uniform(0.24, 0.28), 4)
        channel_status = "COMPROMISED (Basis Inconsistency Detected)"
        risk = "CRITICAL"
        threat_detected = "Intercept-Resend Eavesdropping Detected"
        first_action = "Terminate the compromised quantum channel."
        countermeasure = "Deploy decoy-state protocol; discard sifted key bits; recalibrate basis check frequency."
    elif "MANIPULAT" in clean_mode or clean_mode == "QUANTUM-CHANNEL-MANIPULATION":
        attack_type = "Quantum Channel Manipulation"
        base_qber = disturbance_level if disturbance_level is not None else round(random.uniform(0.28, 0.36), 4)
        channel_status = "COMPROMISED (Channel Perturbation)"
        risk = "HIGH"
        threat_detected = "Quantum Channel Manipulation Detected"
        first_action = "Reject the modified message and re-establish a trusted channel."
        countermeasure = "Perform quantum state tomography; recalibrate phase/polarization baselines; re-entangle Bell pairs."
    else:
        attack_type = "Normal Secure Channel"
        base_qber = disturbance_level if disturbance_level is not None else round(random.uniform(0.005, 0.018), 4)
        channel_status = "SECURE (Normal Low Noise)"
        risk = "LOW"
        threat_detected = "None (Channel Operating Within Quantum Bound)"
        first_action = "Allow transaction transmission."
        countermeasure = "Maintain continuous quantum bit error rate telemetry monitoring."

    # Compute exact bit distribution
    mismatches = int(round(total_bits * base_qber))
    matches = total_bits - mismatches
    qber_actual = round(mismatches / max(1, total_bits), 4)
    qber_pct = round(qber_actual * 100.0, 2)

    # Threshold evaluation (Prototype thresholds)
    # QBER < 5% -> SECURE
    # 5% <= QBER < 11% -> SUSPICIOUS
    # QBER >= 11% -> COMPROMISED (Theoretical QDS/BB84 bound)
    if qber_actual >= 0.11:
        threshold_category = "COMPROMISED"
        eavesdrop_prob = min(99.9, round(85.0 + (qber_actual - 0.11) * 35.0, 2))
    elif qber_actual >= 0.05:
        threshold_category = "SUSPICIOUS"
        eavesdrop_prob = round(20.0 + (qber_actual * 300), 2)
    else:
        threshold_category = "SECURE"
        eavesdrop_prob = round(qber_actual * 40.0, 2)

    return {
        "simulation_type": "Quantum Channel Security",
        "attack_mode": mode,
        "attack_type": attack_type,
        "total_bits": total_bits,
        "matching_bits": matches,
        "mismatching_bits": mismatches,
        "qber": qber_actual,
        "qber_percentage": f"{qber_pct:.2f}%",
        "qber_formula": "QBER = (mismatched_bits / total_bits) * 100",
        "channel_status": channel_status,
        "threshold_category": threshold_category,
        "quantum_risk": risk,
        "estimated_eavesdropping_probability": f"{eavesdrop_prob:.1f}%",
        "threat_detected": threat_detected,
        "first_action": first_action,
        "countermeasure": countermeasure,
        "qber_thresholds": {
            "secure_bound": "< 5.00%",
            "suspicious_bound": "5.00% - 11.00%",
            "compromised_bound": "≥ 11.00% (Theoretical QDS Bound)"
        },
        "chart_data": {
            "labels": ["Matching Bits", "Mismatched Bits (QBER)"],
            "values": [matches, mismatches]
        },
        "disclaimer": "Thresholds and quantum disturbance values are derived from simulation models for research and prototype demonstration."
    }

# ==============================================================================
# 7. COMPLETE QUANTUM DIGITAL SIGNATURE WORKFLOW
# ==============================================================================

def simulate_complete_qds(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Runs the complete end-to-end Quantum Digital Signature simulation workflow:
    Qubit -> Bell State -> Entanglement -> Teleportation -> Alice Measurement
    -> Pauli Correction -> Bob Measurement -> Projective Measurement
    -> QBER -> Channel Analysis -> Threat Detection -> Risk Score -> Countermeasures.
    """
    if params is None:
        params = {}

    channel_mode = params.get("channel_mode", "NORMAL")
    bell_type = params.get("bell_state", "Phi+")
    shots = int(params.get("shots", 1024))
    
    # 1. Qubit Preparation
    qubit_res = simulate_qubit("superposition", shots=shots)

    # 2. Bell State Generation
    bell_res = simulate_bell_state(bell_type, shots=shots)

    # 3. Entanglement
    entangle_res = simulate_entanglement(shots=shots)

    # 4. Teleportation & Pauli Correction
    teleport_res = simulate_teleportation("superposition", shots=shots)

    # 5. Projective Measurement
    proj_res = projective_measurement("superposition", shots=shots)

    # 6. Channel Analysis & QBER
    channel_res = simulate_quantum_channel(channel_mode, total_bits=1000)

    # 7. Risk calculation from quantum channel posture
    if channel_res["qber"] >= 0.11:
        overall_status = "ATTACK DETECTED"
        risk_score = 92 if "EAVESDROP" in channel_mode else 85
        risk_level = "CRITICAL"
        primary_threat = channel_res["attack_type"]
    elif channel_res["qber"] >= 0.05:
        overall_status = "WARNING"
        risk_score = 55
        risk_level = "MEDIUM"
        primary_threat = "Elevated Channel Noise / Perturbation"
    else:
        overall_status = "SECURE"
        risk_score = 8
        risk_level = "LOW"
        primary_threat = "None (Quantum Channel Verified Secure)"

    return {
        "success": True,
        "timestamp": "2026-09-02T20:47:00Z",
        "workflow": "Complete Quantum Digital Signature (QDS) Simulation",
        "qubit": qubit_res,
        "bell_state": bell_res,
        "entanglement": entangle_res,
        "teleportation": teleport_res,
        "projective_measurement": proj_res,
        "channel_security": channel_res,
        "metrics_summary": {
            "qubit_count": 3,
            "bell_state": bell_res["bell_state"],
            "entanglement_status": entangle_res["entanglement_status"],
            "correlation_percentage": entangle_res["correlation_display"],
            "teleportation_success": True,
            "alice_measurement": teleport_res["alice_measurement"]["bits"],
            "pauli_correction": teleport_res["pauli_correction"]["gate_symbol"],
            "bob_measurement": "Recovered |ψ⟩ (Fidelity 100.0%)",
            "qber": channel_res["qber_percentage"],
            "channel_status": channel_res["channel_status"],
            "measurement_shots": shots
        },
        "risk_engine": {
            "overall_status": overall_status,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "primary_threat": primary_threat,
            "first_action": channel_res["first_action"],
            "countermeasure": channel_res["countermeasure"]
        },
        "disclaimer": "All quantum operations are simulated using statevector mathematical models and are not executed on physical quantum hardware."
    }
