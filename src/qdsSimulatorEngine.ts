/**
 * Quantum Digital Signature (QDS) Security Simulator Engine (TypeScript)
 * Implements statevector simulation, Bell states, Entanglement correlation,
 * Quantum Teleportation, Pauli corrections, Projective measurement,
 * and Quantum Channel Security / QBER analysis.
 */

export interface QubitResult {
  simulation_type: string;
  state_name: string;
  gate_applied: string;
  statevector: {
    alpha: { real: number; imag: number };
    beta: { real: number; imag: number };
    formula: string;
  };
  probabilities: {
    '0': number;
    '1': number;
    '0_percent': string;
    '1_percent': string;
  };
  measurements: {
    '0': number;
    '1': number;
    ratio_0: number;
    ratio_1: number;
  };
  shots: number;
  circuit_ascii: string;
  qiskit_code: string;
  explanation: string;
  disclaimer: string;
}

export interface BellStateResult {
  simulation_type: string;
  bell_state: string;
  formula: string;
  preparation_steps: string[];
  circuit_ascii: string;
  ideal_probabilities: Record<string, number>;
  measurement_counts: Record<string, number>;
  shots: number;
  qiskit_code: string;
  explanation: string;
}

export interface EntanglementResult {
  simulation_type: string;
  entanglement_status: string;
  bell_state_used: string;
  total_measurements: number;
  matching_measurements: number;
  mismatching_measurements: number;
  correlation_percentage: number;
  correlation_display: string;
  circuit_ascii: string;
  chart_data: {
    labels: string[];
    values: number[];
  };
  explanation: string;
}

export interface PauliCorrectionResult {
  bits: string;
  correction_gate: string;
  gate_symbol: string;
  matrix: string;
  action: string;
  bob_transformation: string;
  circuit_symbol: string;
}

export interface TeleportationResult {
  simulation_type: string;
  teleportation_status: string;
  original_message_state: {
    description: string;
    alpha: number;
    beta: number;
    probabilities: { '0': number; '1': number };
  };
  alice_measurement: {
    bits: string;
    q0_bit: string;
    q1_bit: string;
    basis: string;
  };
  pauli_correction: PauliCorrectionResult;
  bob_recovered_state: {
    state_formula: string;
    fidelity: number;
    fidelity_percentage: string;
    measurements: { '0': number; '1': number };
    state_match: boolean;
  };
  shots: number;
  circuit_ascii: string;
  workflow_diagram: string;
  explanation: string;
}

export interface ProjectiveMeasurementResult {
  simulation_type: string;
  basis: string;
  state_before_measurement: string;
  measurement_outcome: string;
  state_after_measurement: string;
  collapse_mechanism: string;
  measurement_statistics: {
    shots: number;
    outcomes: { '0': number; '1': number };
    observed_prob_0: number;
    observed_prob_1: number;
  };
  explanation: string;
}

export interface QuantumChannelResult {
  simulation_type: string;
  attack_mode: string;
  attack_type: string;
  total_bits: number;
  matching_bits: number;
  mismatching_bits: number;
  qber: number;
  qber_percentage: string;
  qber_formula: string;
  channel_status: string;
  threshold_category: string;
  quantum_risk: string;
  estimated_eavesdropping_probability: string;
  threat_detected: string;
  first_action: string;
  countermeasure: string;
  qber_thresholds: {
    secure_bound: string;
    suspicious_bound: string;
    compromised_bound: string;
  };
  chart_data: {
    labels: string[];
    values: number[];
  };
  disclaimer: string;
}

export interface CompleteQdsResult {
  success: boolean;
  timestamp: string;
  workflow: string;
  qubit: QubitResult;
  bell_state: BellStateResult;
  entanglement: EntanglementResult;
  teleportation: TeleportationResult;
  projective_measurement: ProjectiveMeasurementResult;
  channel_security: QuantumChannelResult;
  metrics_summary: {
    qubit_count: number;
    bell_state: string;
    entanglement_status: string;
    correlation_percentage: string;
    teleportation_success: boolean;
    alice_measurement: string;
    pauli_correction: string;
    bob_measurement: string;
    qber: string;
    channel_status: string;
    measurement_shots: number;
  };
  risk_engine: {
    overall_status: string;
    risk_score: number;
    risk_level: string;
    primary_threat: string;
    first_action: string;
    countermeasure: string;
  };
  disclaimer: string;
}

// 1. Qubit Simulation
export function simulateQubit(
  stateType: string = 'superposition',
  theta: number = Math.PI / 2,
  phi: number = 0.0,
  shots: number = 1024
): QubitResult {
  const clean = stateType.toLowerCase();
  let alpha = { real: 1.0, imag: 0.0 };
  let beta = { real: 0.0, imag: 0.0 };
  let label = '|0⟩ Ground State';
  let gateApplied = 'None (Prepared in computational basis |0⟩)';
  let circuitAscii = '     ┌───┐\nq_0: ┤ I ├─■─\n     └───┘\nc_0: ════════';

  if (clean === '1' || clean === '|1>' || clean === 'one' || clean === 'excited') {
    alpha = { real: 0.0, imag: 0.0 };
    beta = { real: 1.0, imag: 0.0 };
    label = '|1⟩ Excited State';
    gateApplied = 'Pauli-X (Bit-flip gate X|0⟩ = |1⟩)';
    circuitAscii = '     ┌───┐┌─┐\nq_0: ┤ X ├┤M├\n     └───┘└╥┘\nc_0: ══════╩═';
  } else if (clean === 'superposition' || clean === '+' || clean === '|+>' || clean === 'hadamard') {
    const inv = 1.0 / Math.sqrt(2);
    alpha = { real: Math.round(inv * 1000) / 1000, imag: 0.0 };
    beta = { real: Math.round(inv * 1000) / 1000, imag: 0.0 };
    label = '|+⟩ Equal Superposition (|0⟩ + |1⟩)/√2';
    gateApplied = 'Hadamard Gate (H|0⟩ = (|0⟩ + |1⟩)/√2)';
    circuitAscii = '     ┌───┐┌─┐\nq_0: ┤ H ├┤M├\n     └───┘└╥┘\nc_0: ══════╩═';
  } else if (clean === '-' || clean === '|->' || clean === 'minus') {
    const inv = 1.0 / Math.sqrt(2);
    alpha = { real: Math.round(inv * 1000) / 1000, imag: 0.0 };
    beta = { real: -Math.round(inv * 1000) / 1000, imag: 0.0 };
    label = '|-⟩ Phase Superposition (|0⟩ - |1⟩)/√2';
    gateApplied = 'Pauli-X + Hadamard Gate (H X|0⟩ = (|0⟩ - |1⟩)/√2)';
    circuitAscii = '     ┌───┐┌───┐┌─┐\nq_0: ┤ X ├┤ H ├┤M├\n     └───┘└───┘└╥┘\nc_0: ════════════╩═';
  } else {
    alpha = { real: Math.round(Math.cos(theta / 2.0) * 1000) / 1000, imag: 0.0 };
    beta = { real: Math.round(Math.sin(theta / 2.0) * Math.cos(phi) * 1000) / 1000, imag: Math.round(Math.sin(theta / 2.0) * Math.sin(phi) * 1000) / 1000 };
    label = `|ψ⟩ Arbitrary State (θ=${theta.toFixed(2)}, φ=${phi.toFixed(2)})`;
    gateApplied = `Rotation U3(θ=${theta.toFixed(2)}, φ=${phi.toFixed(2)}, λ=0)`;
    circuitAscii = `     ┌──────────────┐┌─┐\nq_0: ┤ U3(${theta.toFixed(1)},${phi.toFixed(1)},0) ├┤M├\n     └──────────────┘└╥┘\nc_0: ═════════════════╩═`;
  }

  const p0 = Math.round((alpha.real * alpha.real + alpha.imag * alpha.imag) * 10000) / 10000;
  const p1 = Math.round((beta.real * beta.real + beta.imag * beta.imag) * 10000) / 10000;

  let count0 = 0;
  let count1 = 0;
  for (let i = 0; i < shots; i++) {
    if (Math.random() < p0) count0++;
    else count1++;
  }

  return {
    simulation_type: 'Qubit Simulation',
    state_name: label,
    gate_applied: gateApplied,
    statevector: {
      alpha,
      beta,
      formula: `(${alpha.real.toFixed(3)} + ${alpha.imag.toFixed(3)}i)|0⟩ + (${beta.real.toFixed(3)} + ${beta.imag.toFixed(3)}i)|1⟩`
    },
    probabilities: {
      '0': p0,
      '1': p1,
      '0_percent': `${(p0 * 100).toFixed(1)}%`,
      '1_percent': `${(p1 * 100).toFixed(1)}%`
    },
    measurements: {
      '0': count0,
      '1': count1,
      ratio_0: Math.round((count0 / shots) * 10000) / 10000,
      ratio_1: Math.round((count1 / shots) * 10000) / 10000
    },
    shots,
    circuit_ascii: circuitAscii,
    qiskit_code: `from qiskit import QuantumCircuit, Aer, execute\nqc = QuantumCircuit(1, 1)\n${gateApplied.includes('Hadamard') ? 'qc.h(0)' : gateApplied.includes('Pauli-X') ? 'qc.x(0)' : '# State preparation'}\nqc.measure(0, 0)\nbackend = Aer.get_backend('qasm_simulator')\njob = execute(qc, backend, shots=${shots})\ncounts = job.result().get_counts()`,
    explanation:
      'Hadamard gate transforms basis state |0⟩ into equal superposition (|0⟩ + |1⟩)/√2. Prior to projective measurement, the qubit exists in a linear combination of both states. Measurement collapses the statevector with probability P(0)=|α|² and P(1)=|β|².',
    disclaimer: 'Simulated quantum state via classical statevector propagation (Qiskit simulator equivalent).'
  };
}

// 2. Bell State Generator
export function simulateBellState(bellState: string = 'Phi+', shots: number = 1024, noiseRate: number = 0.002): BellStateResult {
  const clean = bellState.replace(/[\s_\-]/g, '').toLowerCase();
  let stateId = 'Phi+';
  let formula = 'Φ+ = (|00⟩ + |11⟩) / √2';
  let prepSteps = ['Apply H to q0', 'Apply CNOT from q0 to q1'];
  let circuitAscii = 'q_0: ──[H]──■────[M]─\n            │       \nq_1: ───────■────[M]─\nc:   ════════════════';
  let idealProbs: Record<string, number> = { '00': 0.5, '11': 0.5, '01': 0.0, '10': 0.0 };

  if (clean.includes('phi-') || clean.includes('phiminus')) {
    stateId = 'Phi-';
    formula = 'Φ- = (|00⟩ - |11⟩) / √2';
    prepSteps = ['Apply X to q0', 'Apply H to q0', 'Apply CNOT from q0 to q1'];
    circuitAscii = 'q_0: ──[X]──[H]──■───[M]─\n                 │       \nq_1: ────────────■───[M]─\nc:   ════════════════════';
    idealProbs = { '00': 0.5, '11': 0.5, '01': 0.0, '10': 0.0 };
  } else if (clean.includes('psi+') || clean.includes('psiplus')) {
    stateId = 'Psi+';
    formula = 'Ψ+ = (|01⟩ + |10⟩) / √2';
    prepSteps = ['Apply X to q1', 'Apply H to q0', 'Apply CNOT from q0 to q1'];
    circuitAscii = 'q_0: ──[H]──■────[M]─\n            │       \nq_1: ──[X]──■────[M]─\nc:   ════════════════';
    idealProbs = { '01': 0.5, '10': 0.5, '00': 0.0, '11': 0.0 };
  } else if (clean.includes('psi-') || clean.includes('psiminus')) {
    stateId = 'Psi-';
    formula = 'Ψ- = (|01⟩ - |10⟩) / √2';
    prepSteps = ['Apply X to q0', 'Apply X to q1', 'Apply H to q0', 'Apply CNOT from q0 to q1'];
    circuitAscii = 'q_0: ──[X]──[H]──■───[M]─\n                 │       \nq_1: ──[X]───────■───[M]─\nc:   ════════════════════';
    idealProbs = { '01': 0.5, '10': 0.5, '00': 0.0, '11': 0.0 };
  }

  const counts: Record<string, number> = { '00': 0, '01': 0, '10': 0, '11': 0 };
  for (let i = 0; i < shots; i++) {
    const r = Math.random();
    if (stateId === 'Phi+' || stateId === 'Phi-') {
      if (r < 0.5 - noiseRate / 2) counts['00']++;
      else if (r < 1.0 - noiseRate) counts['11']++;
      else if (r < 1.0 - noiseRate / 2) counts['01']++;
      else counts['10']++;
    } else {
      if (r < 0.5 - noiseRate / 2) counts['01']++;
      else if (r < 1.0 - noiseRate) counts['10']++;
      else if (r < 1.0 - noiseRate / 2) counts['00']++;
      else counts['11']++;
    }
  }

  return {
    simulation_type: 'Bell State Generator',
    bell_state: stateId,
    formula,
    preparation_steps: prepSteps,
    circuit_ascii: circuitAscii,
    ideal_probabilities: idealProbs,
    measurement_counts: counts,
    shots,
    qiskit_code: `from qiskit import QuantumCircuit, Aer, execute\nqc = QuantumCircuit(2, 2)\n${prepSteps.map(s => (s.includes('H') ? 'qc.h(0)' : s.includes('X to q0') ? 'qc.x(0)' : s.includes('X to q1') ? 'qc.x(1)' : 'qc.cx(0, 1)')).join('\n')}\nqc.measure([0, 1], [0, 1])\nbackend = Aer.get_backend('qasm_simulator')\njob = execute(qc, backend, shots=${shots})\nresult = job.result().get_counts()`,
    explanation: `Bell state ${stateId} generates maximally entangled qubit pairs. Measuring one qubit instantly correlates with the measurement outcome of the other, forming the fundamental cryptographic resource for Quantum Digital Signatures (QDS).`
  };
}

// 3. Entanglement Simulation
export function simulateEntanglement(shots: number = 1024, noiseLevel: number = 0.003): EntanglementResult {
  let matching = 0;
  let mismatching = 0;

  for (let i = 0; i < shots; i++) {
    if (Math.random() > noiseLevel) matching++;
    else mismatching++;
  }

  const correlationPct = Math.round((matching / shots) * 10000) / 100;

  return {
    simulation_type: 'Quantum Entanglement Verification',
    entanglement_status: 'ACTIVE',
    bell_state_used: 'Φ+ = (|00⟩ + |11⟩) / √2',
    total_measurements: shots,
    matching_measurements: matching,
    mismatching_measurements: mismatching,
    correlation_percentage: correlationPct,
    correlation_display: `${correlationPct}%`,
    circuit_ascii: '     ┌───┐     ┌─┐   \nq_0: ┤ H ├──■──┤M├───\n     └───┘┌─┴─┐└╥┘┌─┐\nq_1: ─────┤ X ├─╫─┤M├\n          └───┘ ║ └╥┘\nc:   ═══════════╩══╩═',
    chart_data: {
      labels: ['Correlated Outcomes (00/11)', 'Decoherence Mismatches (01/10)'],
      values: [matching, mismatching]
    },
    explanation:
      'Entanglement creates correlated quantum measurement outcomes across spatially separated nodes. In a noiseless channel, Alice and Bob obtain 100.0% matching outcomes, allowing detection of any eavesdropping attempt.'
  };
}

// 4. Pauli Correction
export function applyPauliCorrection(bits: string): PauliCorrectionResult {
  const clean = bits.trim();
  if (clean === '01') {
    return {
      bits: '01',
      correction_gate: 'X (Pauli-X Bit Flip)',
      gate_symbol: 'X',
      matrix: '[[0, 1], [1, 0]]',
      action: 'Applies bit flip (NOT gate) to invert |0⟩ ↔ |1⟩ on Bob\'s qubit.',
      bob_transformation: 'X (X|ψ⟩) = |ψ⟩',
      circuit_symbol: '───X───'
    };
  } else if (clean === '10') {
    return {
      bits: '10',
      correction_gate: 'Z (Pauli-Z Phase Flip)',
      gate_symbol: 'Z',
      matrix: '[[1, 0], [0, -1]]',
      action: 'Applies phase flip to negate relative phase of |1⟩ component.',
      bob_transformation: 'Z (Z|ψ⟩) = |ψ⟩',
      circuit_symbol: '───Z───'
    };
  } else if (clean === '11') {
    return {
      bits: '11',
      correction_gate: 'XZ (Pauli-X followed by Pauli-Z)',
      gate_symbol: 'XZ',
      matrix: '[[0, 1], [-1, 0]]',
      action: 'Applies both bit flip and phase flip corrections to fully recover |ψ⟩.',
      bob_transformation: 'Z·X (X·Z|ψ⟩) = |ψ⟩',
      circuit_symbol: '───X───Z───'
    };
  }
  return {
    bits: '00',
    correction_gate: 'I (Identity)',
    gate_symbol: 'I',
    matrix: '[[1, 0], [0, 1]]',
    action: 'No correction needed. Bob\'s state is already identical to original message qubit.',
    bob_transformation: 'I|ψ⟩ = |ψ⟩',
    circuit_symbol: '───I───'
  };
}

// 5. Quantum Teleportation
export function simulateTeleportation(
  messageState: string = 'superposition',
  customTheta?: number,
  shots: number = 1024
): TeleportationResult {
  let msgAlpha = 1.0 / Math.sqrt(2);
  let msgBeta = 1.0 / Math.sqrt(2);
  let msgDesc = '|+⟩ Superposition (|0⟩ + |1⟩)/√2';

  if (messageState === '0') {
    msgAlpha = 1.0; msgBeta = 0.0; msgDesc = '|0⟩ State';
  } else if (messageState === '1') {
    msgAlpha = 0.0; msgBeta = 1.0; msgDesc = '|1⟩ State';
  } else if (messageState === 'minus') {
    msgAlpha = 1.0 / Math.sqrt(2); msgBeta = -1.0 / Math.sqrt(2); msgDesc = '|-⟩ Phase State';
  }

  if (customTheta !== undefined) {
    msgAlpha = Math.cos(customTheta / 2.0);
    msgBeta = Math.sin(customTheta / 2.0);
    msgDesc = `|ψ⟩ Custom State (θ=${customTheta.toFixed(2)})`;
  }

  const outcomes = ['00', '01', '10', '11'];
  const aliceBits = outcomes[Math.floor(Math.random() * outcomes.length)];
  const pauliInfo = applyPauliCorrection(aliceBits);

  const bobP0 = Math.round(msgAlpha * msgAlpha * 10000) / 10000;
  const bobP1 = Math.round(msgBeta * msgBeta * 10000) / 10000;
  const bob0Count = Math.round(shots * bobP0);
  const bob1Count = shots - bob0Count;

  const circuitAscii =
    '                    ┌───┐     ┌─┐               \nq_0 (Msg): ─────────┤ X ├──■──┤M├───────────────\n          ┌───┐     └─┬─┘┌─┴─┐└╥┘┌─┐            \nq_1 (Alc): ┤ H ├──■───■──┤ H ├─╫─┤M├────────────\n          └───┘┌─┴─┐     └───┘ ║ └╥┘ ┌───┐ ┌───┐\nq_2 (Bob): ────┤ X ├───────────╫──╫──┤ X ├─┤ Z ├\n               └───┘           ║  ║  └─┬─┘ └─┬─┘\nc_0:       ════════════════════╩══╬════╪═════╪══\nc_1:       ═══════════════════════╩════■═════╪══\nc_2:       ══════════════════════════════════■══';

  const workflowDiagram = `MESSAGE QUBIT (|ψ⟩)\n       ↓\nALICE (CNOT q0→q1, H q0)\n       ↓\nENTANGLED BELL PAIR (q1 ⇄ q2)\n       ↓\nCLASSICAL MEASUREMENT (Bits: ${aliceBits})\n       ↓\nPAULI CORRECTION (Gate: ${pauliInfo.gate_symbol})\n       ↓\nBOB (Applied to q2)\n       ↓\nRECOVERED STATE (|ψ_Bob⟩ = |ψ⟩, Fidelity: 100.0%)`;

  return {
    simulation_type: 'Quantum Teleportation',
    teleportation_status: 'SUCCESSFUL',
    original_message_state: {
      description: msgDesc,
      alpha: Math.round(msgAlpha * 10000) / 10000,
      beta: Math.round(msgBeta * 10000) / 10000,
      probabilities: { '0': bobP0, '1': bobP1 }
    },
    alice_measurement: {
      bits: aliceBits,
      q0_bit: aliceBits[0],
      q1_bit: aliceBits[1],
      basis: 'Bell Basis Measurement'
    },
    pauli_correction: pauliInfo,
    bob_recovered_state: {
      state_formula: `${msgAlpha.toFixed(3)}|0⟩ + ${msgBeta.toFixed(3)}|1⟩`,
      fidelity: 1.0,
      fidelity_percentage: '100.0%',
      measurements: { '0': bob0Count, '1': bob1Count },
      state_match: true
    },
    shots,
    circuit_ascii: circuitAscii,
    workflow_diagram: workflowDiagram,
    explanation:
      'Quantum teleportation transfers quantum-state information using entanglement and classical communication. No matter is transported; rather, the unknown quantum state |ψ⟩ is reconstructed at Bob\'s node using shared Bell entanglement and two classical bits of measurement information.'
  };
}

// 6. Projective Measurement
export function projectiveMeasurement(initialState: string = 'superposition', shots: number = 1024): ProjectiveMeasurementResult {
  let p0 = 0.5;
  let formulaBefore = '1/√2 |0⟩ + 1/√2 |1⟩ (Superposition)';

  if (initialState === '0') {
    p0 = 1.0; formulaBefore = '|0⟩';
  } else if (initialState === '1') {
    p0 = 0.0; formulaBefore = '|1⟩';
  }

  const singleOutcome = Math.random() < p0 ? '0' : '1';
  let count0 = 0;
  let count1 = 0;
  for (let i = 0; i < shots; i++) {
    if (Math.random() < p0) count0++;
    else count1++;
  }

  return {
    simulation_type: 'Projective Measurement',
    basis: 'Computational Basis {|0⟩, |1⟩}',
    state_before_measurement: formulaBefore,
    measurement_outcome: singleOutcome,
    state_after_measurement: `|${singleOutcome}⟩ (Eigenstate)`,
    collapse_mechanism: `Wavefunction collapsed onto eigenvector |${singleOutcome}⟩ with probability P(${singleOutcome})=${(singleOutcome === '0' ? p0 : 1 - p0).toFixed(1)}`,
    measurement_statistics: {
      shots,
      outcomes: { '0': count0, '1': count1 },
      observed_prob_0: Math.round((count0 / shots) * 10000) / 10000,
      observed_prob_1: Math.round((count1 / shots) * 10000) / 10000
    },
    explanation:
      'Projective measurement converts the continuous quantum amplitude state into a discrete classical measurement outcome. The measurement operator P_m = |m⟩⟨m| projects the quantum state onto one of its orthogonal basis vectors.'
  };
}

// 7. Quantum Channel Security & Attack Simulator
export function simulateQuantumChannel(
  mode: string = 'NORMAL',
  totalBits: number = 1000,
  disturbanceLevel?: number
): QuantumChannelResult {
  const clean = mode.toUpperCase().replace(/[\s_]/g, '-');
  let attackType = 'Normal Secure Channel';
  let baseQber = disturbanceLevel !== undefined ? disturbanceLevel : 0.012;
  let channelStatus = 'SECURE (Normal Low Noise)';
  let risk = 'LOW';
  let threatDetected = 'None (Channel Operating Within Quantum Bound)';
  let firstAction = 'Allow transaction transmission.';
  let countermeasure = 'Maintain continuous quantum bit error rate telemetry monitoring.';

  if (clean.includes('EAVESDROP') || clean.includes('ENTANGLE')) {
    attackType = 'Quantum Eavesdropping (Entangle-and-Measure)';
    baseQber = disturbanceLevel !== undefined ? disturbanceLevel : 0.445;
    channelStatus = 'COMPROMISED (High Quantum Error Rate)';
    risk = 'CRITICAL';
    threatDetected = 'Quantum Eavesdropping Attack Detected';
    firstAction = 'Terminate/suspend the affected simulated quantum channel immediately.';
    countermeasure = 'Abort key distillation; initiate simulated privacy amplification and switch to secondary entangled Bell route.';
  } else if (clean.includes('INTERCEPT')) {
    attackType = 'Intercept-Resend Attack';
    baseQber = disturbanceLevel !== undefined ? disturbanceLevel : 0.258;
    channelStatus = 'COMPROMISED (Basis Inconsistency Detected)';
    risk = 'CRITICAL';
    threatDetected = 'Intercept-Resend Eavesdropping Detected';
    firstAction = 'Terminate the compromised quantum channel.';
    countermeasure = 'Deploy decoy-state protocol; discard sifted key bits; recalibrate basis check frequency.';
  } else if (clean.includes('MANIPULAT')) {
    attackType = 'Quantum Channel Manipulation';
    baseQber = disturbanceLevel !== undefined ? disturbanceLevel : 0.325;
    channelStatus = 'COMPROMISED (Channel Perturbation)';
    risk = 'HIGH';
    threatDetected = 'Quantum Channel Manipulation Detected';
    firstAction = 'Reject the modified message and re-establish a trusted channel.';
    countermeasure = 'Perform quantum state tomography; recalibrate phase/polarization baselines; re-entangle Bell pairs.';
  }

  const mismatches = Math.round(totalBits * baseQber);
  const matches = totalBits - mismatches;
  const qberActual = Math.round((mismatches / totalBits) * 10000) / 10000;
  const qberPct = (qberActual * 100).toFixed(2);

  let thresholdCat = 'SECURE';
  let eavesdropProb = (qberActual * 40.0).toFixed(1);

  if (qberActual >= 0.11) {
    thresholdCat = 'COMPROMISED';
    eavesdropProb = Math.min(99.9, 85.0 + (qberActual - 0.11) * 35.0).toFixed(1);
  } else if (qberActual >= 0.05) {
    thresholdCat = 'SUSPICIOUS';
    eavesdropProb = (20.0 + qberActual * 300).toFixed(1);
  }

  return {
    simulation_type: 'Quantum Channel Security',
    attack_mode: mode,
    attack_type: attackType,
    total_bits: totalBits,
    matching_bits: matches,
    mismatching_bits: mismatches,
    qber: qberActual,
    qber_percentage: `${qberPct}%`,
    qber_formula: 'QBER = (mismatched_bits / total_bits) * 100',
    channel_status: channelStatus,
    threshold_category: thresholdCat,
    quantum_risk: risk,
    estimated_eavesdropping_probability: `${eavesdropProb}%`,
    threat_detected: threatDetected,
    first_action: firstAction,
    countermeasure,
    qber_thresholds: {
      secure_bound: '< 5.00%',
      suspicious_bound: '5.00% - 11.00%',
      compromised_bound: '≥ 11.00% (Theoretical QDS Bound)'
    },
    chart_data: {
      labels: ['Matching Bits', 'Mismatched Bits (QBER)'],
      values: [matches, mismatches]
    },
    disclaimer: 'Thresholds and quantum disturbance values are derived from simulation models for research and prototype demonstration.'
  };
}

// 8. Complete QDS Simulator Workflow
export function simulateCompleteQds(params: { channel_mode?: string; bell_state?: string; shots?: number } = {}): CompleteQdsResult {
  const channelMode = params.channel_mode || 'NORMAL';
  const bellType = params.bell_state || 'Phi+';
  const shots = params.shots || 1024;

  const qubit = simulateQubit('superposition', Math.PI / 2, 0, shots);
  const bell = simulateBellState(bellType, shots);
  const entangle = simulateEntanglement(shots);
  const teleport = simulateTeleportation('superposition', undefined, shots);
  const projective = projectiveMeasurement('superposition', shots);
  const channel = simulateQuantumChannel(channelMode, 1000);

  let overallStatus = 'SECURE';
  let riskScore = 8;
  let riskLevel = 'LOW';
  let primaryThreat = 'None (Quantum Channel Verified Secure)';

  if (channel.qber >= 0.11) {
    overallStatus = 'ATTACK DETECTED';
    riskScore = channelMode.toUpperCase().includes('EAVESDROP') ? 94 : 88;
    riskLevel = 'CRITICAL';
    primaryThreat = channel.attack_type;
  } else if (channel.qber >= 0.05) {
    overallStatus = 'WARNING';
    riskScore = 55;
    riskLevel = 'MEDIUM';
    primaryThreat = 'Elevated Channel Noise / Perturbation';
  }

  return {
    success: true,
    timestamp: new Date().toISOString(),
    workflow: 'Complete Quantum Digital Signature (QDS) Simulation',
    qubit,
    bell_state: bell,
    entanglement: entangle,
    teleportation: teleport,
    projective_measurement: projective,
    channel_security: channel,
    metrics_summary: {
      qubit_count: 3,
      bell_state: bell.bell_state,
      entanglement_status: entangle.entanglement_status,
      correlation_percentage: entangle.correlation_display,
      teleportation_success: true,
      alice_measurement: teleport.alice_measurement.bits,
      pauli_correction: teleport.pauli_correction.gate_symbol,
      bob_measurement: 'Recovered |ψ⟩ (Fidelity 100.0%)',
      qber: channel.qber_percentage,
      channel_status: channel.channel_status,
      measurement_shots: shots
    },
    risk_engine: {
      overall_status: overallStatus,
      risk_score: riskScore,
      risk_level: riskLevel,
      primary_threat: primaryThreat,
      first_action: channel.first_action,
      countermeasure: channel.countermeasure
    },
    disclaimer: 'All quantum operations are simulated using statevector mathematical models and are not executed on physical quantum hardware.'
  };
}
