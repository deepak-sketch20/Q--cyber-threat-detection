import React, { useState, useEffect } from 'react';
import {
  Atom,
  Zap,
  Activity,
  ShieldAlert,
  ShieldCheck,
  Send,
  Cpu,
  RefreshCw,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Layers,
  BarChart3,
  Network,
  Radio,
  ArrowRight,
  Info
} from 'lucide-react';
import {
  simulateQubit,
  simulateBellState,
  simulateEntanglement,
  simulateTeleportation,
  applyPauliCorrection,
  simulateQuantumChannel,
  simulateCompleteQds,
  projectiveMeasurement,
  QubitResult,
  BellStateResult,
  EntanglementResult,
  TeleportationResult,
  QuantumChannelResult,
  CompleteQdsResult
} from '../qdsSimulatorEngine';

export const QuantumSecurityLab: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'pipeline' | 'qubit' | 'bell' | 'entanglement' | 'teleportation' | 'channel'>('pipeline');
  const [loading, setLoading] = useState(false);

  // 1. Qubit Lab State
  const [qubitState, setQubitState] = useState<string>('superposition');
  const [qubitTheta, setQubitTheta] = useState<number>(1.57);
  const [qubitShots, setQubitShots] = useState<number>(1024);
  const [qubitResult, setQubitResult] = useState<QubitResult | null>(null);

  // 2. Bell State
  const [selectedBell, setSelectedBell] = useState<string>('Phi+');
  const [bellShots, setBellShots] = useState<number>(1024);
  const [bellResult, setBellResult] = useState<BellStateResult | null>(null);

  // 3. Entanglement
  const [entangleShots, setEntangleShots] = useState<number>(1024);
  const [entangleNoise, setEntangleNoise] = useState<number>(0.003);
  const [entangleResult, setEntangleResult] = useState<EntanglementResult | null>(null);

  // 4. Teleportation
  const [teleportMsgState, setTeleportMsgState] = useState<string>('superposition');
  const [teleportResult, setTeleportResult] = useState<TeleportationResult | null>(null);

  // 5. Channel Security
  const [channelMode, setChannelMode] = useState<string>('NORMAL');
  const [channelBits, setChannelBits] = useState<number>(1000);
  const [channelResult, setChannelResult] = useState<QuantumChannelResult | null>(null);

  // 6. Complete Pipeline
  const [pipelineResult, setPipelineResult] = useState<CompleteQdsResult | null>(null);

  useEffect(() => {
    runPipeline();
    runQubit();
    runBell();
    runEntanglement();
    runTeleportation();
    runChannel();
  }, []);

  const runQubit = async () => {
    setLoading(true);
    try {
      const res = simulateQubit(qubitState, qubitTheta, 0, qubitShots);
      setQubitResult(res);
    } finally {
      setLoading(false);
    }
  };

  const runBell = async () => {
    setLoading(true);
    try {
      const res = simulateBellState(selectedBell, bellShots);
      setBellResult(res);
    } finally {
      setLoading(false);
    }
  };

  const runEntanglement = async () => {
    setLoading(true);
    try {
      const res = simulateEntanglement(entangleShots, entangleNoise);
      setEntangleResult(res);
    } finally {
      setLoading(false);
    }
  };

  const runTeleportation = async () => {
    setLoading(true);
    try {
      const res = simulateTeleportation(teleportMsgState, undefined, 1024);
      setTeleportResult(res);
    } finally {
      setLoading(false);
    }
  };

  const runChannel = async (modeOverride?: string) => {
    setLoading(true);
    const mode = modeOverride || channelMode;
    try {
      const res = simulateQuantumChannel(mode, channelBits);
      setChannelResult(res);
    } finally {
      setLoading(false);
    }
  };

  const runPipeline = async (channelOverride?: string) => {
    setLoading(true);
    const mode = channelOverride || channelMode;
    try {
      const res = simulateCompleteQds({ channel_mode: mode, bell_state: selectedBell, shots: 1024 });
      setPipelineResult(res);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="quantum-security-lab-container" className="space-y-5">
      {/* Research Header Banner */}
      <div className="bg-white border border-[#DADCE0] rounded-md p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base font-bold text-[#202124] tracking-tight">
              Quantum Security Simulation
            </h3>
            <span className="text-[11px] font-mono px-2 py-0.5 bg-[#F5F6F8] text-[#5F6368] border border-[#DADCE0] rounded">
              Local Qiskit Aer Equivalent
            </span>
          </div>
          <p className="text-xs text-[#5F6368] mt-1">
            Qiskit-based simulation for digital-signature security research. Uses statevector algebra and Bell-pair entanglement.
          </p>
        </div>
        <button
          onClick={() => {
            runPipeline();
            runQubit();
            runBell();
            runEntanglement();
            runTeleportation();
            runChannel();
          }}
          disabled={loading}
          className="px-3.5 py-1.5 bg-[#2457A6] hover:bg-[#1E4B8F] text-white text-xs font-semibold rounded transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Run Simulation</span>
        </button>
      </div>

      {/* Laboratory Module Navigation Tabs */}
      <div className="flex items-center gap-1 border-b border-[#DADCE0] bg-white px-2 pt-2 rounded-t-md overflow-x-auto">
        {[
          { id: 'pipeline', label: '1. End-to-End QDS' },
          { id: 'qubit', label: '2. Qubit Lab' },
          { id: 'bell', label: '3. Bell State' },
          { id: 'entanglement', label: '4. Entanglement' },
          { id: 'teleportation', label: '5. Teleportation & Pauli' },
          { id: 'channel', label: '6. Quantum Channel & QBER' },
        ].map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3.5 py-2 text-xs font-medium border-b-2 transition -mb-[1px] whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'border-[#2457A6] text-[#2457A6] font-bold bg-[#F5F6F8]'
                  : 'border-transparent text-[#5F6368] hover:text-[#202124] hover:bg-[#F5F6F8]'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* ========================================================================= */}
      {/* 1. END-TO-END PIPELINE */}
      {/* ========================================================================= */}
      {activeTab === 'pipeline' && pipelineResult && (
        <div className="space-y-4">
          {/* Summary Panel */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="bg-white border border-[#DADCE0] rounded-md p-3.5">
              <div className="text-[11px] font-semibold text-[#5F6368] uppercase tracking-wide">Protocol</div>
              <div className="text-sm font-bold text-[#202124] mt-1">3-Qubit Teleportation</div>
              <div className="text-[11px] text-[#5F6368] mt-0.5 font-mono">Bell Entangled (Φ+)</div>
            </div>

            <div className="bg-white border border-[#DADCE0] rounded-md p-3.5">
              <div className="text-[11px] font-semibold text-[#5F6368] uppercase tracking-wide">Channel QBER</div>
              <div className={`text-sm font-bold font-mono mt-1 ${
                pipelineResult.channel_security.qber < 0.05 ? 'text-[#2E7D32]' : 'text-[#C62828]'
              }`}>
                {pipelineResult.channel_security.qber_percentage}
              </div>
              <div className="text-[11px] text-[#5F6368] mt-0.5">Threshold Limit: 11.0%</div>
            </div>

            <div className="bg-white border border-[#DADCE0] rounded-md p-3.5">
              <div className="text-[11px] font-semibold text-[#5F6368] uppercase tracking-wide">Fidelity Recovery</div>
              <div className="text-sm font-bold text-[#2E7D32] font-mono mt-1">100.0%</div>
              <div className="text-[11px] text-[#5F6368] mt-0.5">Pauli Gate: {pipelineResult.teleportation.pauli_correction.gate_symbol}</div>
            </div>

            <div className="bg-white border border-[#DADCE0] rounded-md p-3.5">
              <div className="text-[11px] font-semibold text-[#5F6368] uppercase tracking-wide">Risk Assessment</div>
              <div className={`text-sm font-bold font-mono mt-1 ${
                pipelineResult.risk_engine.risk_score >= 60 ? 'text-[#C62828]' : 'text-[#2E7D32]'
              }`}>
                {pipelineResult.risk_engine.risk_score} / 100 ({pipelineResult.risk_engine.risk_level})
              </div>
              <div className="text-[11px] text-[#5F6368] mt-0.5 truncate">{pipelineResult.risk_engine.primary_threat}</div>
            </div>
          </div>

          {/* Lifecycle Steps */}
          <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#DADCE0] pb-3">
              <div>
                <h4 className="text-xs font-bold text-[#202124] uppercase tracking-wider">
                  QDS Simulation Lifecycle
                </h4>
                <p className="text-xs text-[#5F6368]">
                  Statevector propagation through preparation, entanglement, classical reconciliation, and recovery
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setChannelMode('NORMAL');
                    runPipeline('NORMAL');
                  }}
                  className={`px-2.5 py-1 text-xs font-medium rounded border cursor-pointer ${
                    channelMode === 'NORMAL'
                      ? 'bg-[#E8F5E9] text-[#2E7D32] border-[#C8E6C9] font-bold'
                      : 'bg-white text-[#5F6368] border-[#DADCE0]'
                  }`}
                >
                  Normal Channel
                </button>
                <button
                  onClick={() => {
                    setChannelMode('QUANTUM-EAVESDROPPING');
                    runPipeline('QUANTUM-EAVESDROPPING');
                  }}
                  className={`px-2.5 py-1 text-xs font-medium rounded border cursor-pointer ${
                    channelMode === 'QUANTUM-EAVESDROPPING'
                      ? 'bg-[#FFEBEE] text-[#C62828] border-[#FFCDD2] font-bold'
                      : 'bg-white text-[#5F6368] border-[#DADCE0]'
                  }`}
                >
                  Simulate Eavesdropping
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="border border-[#DADCE0] rounded p-3 bg-[#F5F6F8]">
                <div className="text-[11px] font-bold text-[#2457A6] uppercase mb-1">Step 1: Preparation</div>
                <div className="text-xs font-semibold text-[#202124]">Qubit Superposition |ψ⟩</div>
                <div className="text-[11px] font-mono text-[#5F6368] mt-1">H|0⟩ = (|0⟩ + |1⟩)/√2</div>
                <div className="text-[10px] text-[#2E7D32] font-semibold mt-2">✓ Statevector initialized</div>
              </div>

              <div className="border border-[#DADCE0] rounded p-3 bg-[#F5F6F8]">
                <div className="text-[11px] font-bold text-[#2457A6] uppercase mb-1">Step 2: Entanglement</div>
                <div className="text-xs font-semibold text-[#202124]">Bell State Φ+ Pair</div>
                <div className="text-[11px] font-mono text-[#5F6368] mt-1">H(q1) → CNOT(q1, q2)</div>
                <div className="text-[10px] text-[#2E7D32] font-semibold mt-2">✓ {pipelineResult.entanglement.correlation_display} correlated</div>
              </div>

              <div className="border border-[#DADCE0] rounded p-3 bg-[#F5F6F8]">
                <div className="text-[11px] font-bold text-[#2457A6] uppercase mb-1">Step 3: Alice Measurement</div>
                <div className="text-xs font-semibold text-[#202124]">Joint Bell Projection</div>
                <div className="text-[11px] font-mono text-[#202124] mt-1 font-bold">
                  Bits: {pipelineResult.teleportation.alice_measurement.bits}
                </div>
                <div className="text-[10px] text-[#5F6368] mt-2">Classical link sent to Bob</div>
              </div>

              <div className="border border-[#DADCE0] rounded p-3 bg-[#F5F6F8]">
                <div className="text-[11px] font-bold text-[#2457A6] uppercase mb-1">Step 4: Bob Recovery</div>
                <div className="text-xs font-semibold text-[#202124]">Pauli Correction</div>
                <div className="text-[11px] font-mono text-[#202124] mt-1 font-bold">
                  Gate: {pipelineResult.teleportation.pauli_correction.gate_symbol}
                </div>
                <div className="text-[10px] text-[#2E7D32] font-semibold mt-2">✓ State Fidelity: 100.0%</div>
              </div>
            </div>

            {/* Technical Channel Table */}
            <div className="border border-[#DADCE0] rounded p-3.5 bg-white space-y-2">
              <div className="text-xs font-bold text-[#202124] uppercase tracking-wide">
                Channel Security & Response Playbook
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-2.5 bg-[#F5F6F8] rounded border border-[#DADCE0]">
                  <span className="font-semibold text-[#5F6368] block mb-1">First Action:</span>
                  <p className="font-mono text-[#202124] text-[11px] leading-relaxed">
                    {pipelineResult.channel_security.first_action}
                  </p>
                </div>
                <div className="p-2.5 bg-[#F5F6F8] rounded border border-[#DADCE0]">
                  <span className="font-semibold text-[#5F6368] block mb-1">Countermeasure:</span>
                  <p className="text-[#202124] text-[11px] leading-relaxed">
                    {pipelineResult.channel_security.countermeasure}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. QUBIT LABORATORY */}
      {/* ========================================================================= */}
      {activeTab === 'qubit' && qubitResult && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-4">
            <h4 className="text-xs font-bold text-[#202124] uppercase tracking-wide">
              Qubit Parameter Controls
            </h4>

            <div>
              <label className="block text-xs font-semibold text-[#5F6368] mb-1.5">Preset Quantum State</label>
              <div className="grid grid-cols-2 gap-1.5">
                {[
                  { id: '0', label: '|0⟩ Ground' },
                  { id: '1', label: '|1⟩ Excited (X)' },
                  { id: 'superposition', label: '|+⟩ Equal (H)' },
                  { id: 'minus', label: '|-⟩ Phase (HX)' },
                ].map((s) => (
                  <button
                    key={s.id}
                    onClick={() => {
                      setQubitState(s.id);
                      setTimeout(runQubit, 50);
                    }}
                    className={`px-2.5 py-1.5 text-xs rounded border text-left font-mono cursor-pointer transition ${
                      qubitState === s.id
                        ? 'bg-[#2457A6] text-white border-[#2457A6] font-bold'
                        : 'bg-white text-[#5F6368] border-[#DADCE0] hover:bg-[#F5F6F8]'
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-[#5F6368] mb-1">
                <span>Bloch Sphere Angle θ</span>
                <span className="font-mono font-bold text-[#202124]">{qubitTheta.toFixed(2)} rad</span>
              </div>
              <input
                type="range"
                min="0"
                max="3.1415"
                step="0.05"
                value={qubitTheta}
                onChange={(e) => {
                  setQubitTheta(parseFloat(e.target.value));
                  setQubitState('arbitrary');
                }}
                className="w-full accent-[#2457A6]"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#5F6368] mb-1">Measurement Shots</label>
              <select
                value={qubitShots}
                onChange={(e) => setQubitShots(parseInt(e.target.value, 10))}
                className="w-full bg-white border border-[#DADCE0] rounded px-3 py-1.5 text-xs text-[#202124]"
              >
                <option value={100}>100 Shots</option>
                <option value={1024}>1,024 Shots (Standard Aer)</option>
                <option value={4096}>4,096 Shots (High Precision)</option>
              </select>
            </div>

            <button
              onClick={runQubit}
              disabled={loading}
              className="w-full py-2 bg-[#2457A6] hover:bg-[#1E4B8F] text-white text-xs font-semibold rounded transition cursor-pointer"
            >
              Run Qubit Simulation
            </button>
          </div>

          <div className="lg:col-span-2 bg-white border border-[#DADCE0] rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-[#DADCE0] pb-3">
              <div>
                <h4 className="text-sm font-bold text-[#202124]">{qubitResult.state_name}</h4>
                <div className="text-xs font-mono text-[#5F6368] mt-0.5">{qubitResult.gate_applied}</div>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 bg-[#F5F6F8] text-[#202124] border border-[#DADCE0] rounded font-bold">
                {qubitResult.statevector.formula}
              </span>
            </div>

            <div>
              <div className="text-xs font-bold text-[#5F6368] uppercase tracking-wide mb-2">
                Measurement Probability Collapse ({qubitResult.shots} Shots)
              </div>
              <div className="space-y-2">
                <div>
                  <div className="flex justify-between text-xs font-mono text-[#202124] mb-1">
                    <span>Outcome |0⟩ (P: {qubitResult.probabilities['0_percent']})</span>
                    <span>{qubitResult.measurements['0']} counts ({((qubitResult.measurements['0'] / qubitResult.shots) * 100).toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-[#F5F6F8] border border-[#DADCE0] rounded h-3 overflow-hidden">
                    <div
                      className="bg-[#2457A6] h-full"
                      style={{ width: `${qubitResult.probabilities['0'] * 100}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-[#202124] mb-1">
                    <span>Outcome |1⟩ (P: {qubitResult.probabilities['1_percent']})</span>
                    <span>{qubitResult.measurements['1']} counts ({((qubitResult.measurements['1'] / qubitResult.shots) * 100).toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-[#F5F6F8] border border-[#DADCE0] rounded h-3 overflow-hidden">
                    <div
                      className="bg-[#5F6368] h-full"
                      style={{ width: `${qubitResult.probabilities['1'] * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>

            <div>
              <div className="text-xs font-bold text-[#5F6368] uppercase tracking-wide mb-1">
                Quantum Circuit Diagram (QASM)
              </div>
              <pre className="bg-[#F5F6F8] p-3 rounded border border-[#DADCE0] text-xs font-mono text-[#202124] overflow-x-auto">
                {qubitResult.circuit_ascii}
              </pre>
            </div>

            <p className="text-xs text-[#5F6368] bg-[#F5F6F8] p-2.5 rounded border border-[#DADCE0]">
              {qubitResult.explanation}
            </p>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. BELL STATE GENERATOR */}
      {/* ========================================================================= */}
      {activeTab === 'bell' && bellResult && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
            <h4 className="text-xs font-bold text-[#202124] uppercase tracking-wide">
              Select Bell State
            </h4>

            <div className="space-y-1.5">
              {[
                { id: 'Phi+', label: 'Φ+ = (|00⟩ + |11⟩)/√2', desc: 'Correlated (00, 11)' },
                { id: 'Phi-', label: 'Φ- = (|00⟩ - |11⟩)/√2', desc: 'Phase-inverted (00, 11)' },
                { id: 'Psi+', label: 'Ψ+ = (|01⟩ + |10⟩)/√2', desc: 'Anti-correlated (01, 10)' },
                { id: 'Psi-', label: 'Ψ- = (|01⟩ - |10⟩)/√2', desc: 'Singlet state (01, 10)' },
              ].map((b) => (
                <button
                  key={b.id}
                  onClick={() => {
                    setSelectedBell(b.id);
                    setTimeout(runBell, 50);
                  }}
                  className={`w-full p-2.5 text-left rounded border transition cursor-pointer ${
                    selectedBell === b.id
                      ? 'bg-[#2457A6] text-white border-[#2457A6]'
                      : 'bg-white text-[#202124] border-[#DADCE0] hover:bg-[#F5F6F8]'
                  }`}
                >
                  <div className={`text-xs font-mono font-bold ${selectedBell === b.id ? 'text-white' : 'text-[#202124]'}`}>{b.label}</div>
                  <div className={`text-[11px] mt-0.5 ${selectedBell === b.id ? 'text-white/80' : 'text-[#5F6368]'}`}>{b.desc}</div>
                </button>
              ))}
            </div>

            <button
              onClick={runBell}
              disabled={loading}
              className="w-full py-2 bg-[#2457A6] hover:bg-[#1E4B8F] text-white text-xs font-semibold rounded transition cursor-pointer"
            >
              Generate Bell State
            </button>
          </div>

          <div className="lg:col-span-2 bg-white border border-[#DADCE0] rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-[#DADCE0] pb-3">
              <div>
                <h4 className="text-sm font-bold text-[#202124]">Bell State: {bellResult.bell_state}</h4>
                <div className="text-xs font-mono text-[#5F6368] mt-0.5">{bellResult.formula}</div>
              </div>
              <div className="text-xs font-mono text-[#5F6368]">
                {bellResult.shots} Total Shots
              </div>
            </div>

            <div>
              <div className="text-xs font-bold text-[#5F6368] uppercase tracking-wide mb-2">
                2-Qubit Computational Basis Measurement Distribution
              </div>
              <div className="grid grid-cols-4 gap-2">
                {['00', '01', '10', '11'].map((basis) => {
                  const count = bellResult.measurement_counts[basis] || 0;
                  const pct = ((count / bellResult.shots) * 100).toFixed(1);
                  const isExpected = (bellResult.ideal_probabilities[basis] || 0) > 0;
                  return (
                    <div
                      key={basis}
                      className={`p-3 rounded border text-center font-mono ${
                        isExpected ? 'bg-[#F5F6F8] border-[#2457A6] text-[#2457A6]' : 'bg-white border-[#DADCE0] text-[#5F6368]'
                      }`}
                    >
                      <div className="text-xs font-bold">|{basis}⟩</div>
                      <div className="text-base font-bold mt-1">{pct}%</div>
                      <div className="text-[10px] text-[#5F6368] mt-0.5">{count} counts</div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="text-xs font-bold text-[#5F6368] uppercase tracking-wide mb-1">
                Preparation Circuit
              </div>
              <pre className="bg-[#F5F6F8] p-3 rounded border border-[#DADCE0] text-xs font-mono text-[#202124] overflow-x-auto">
                {bellResult.circuit_ascii}
              </pre>
            </div>

            <p className="text-xs text-[#5F6368] bg-[#F5F6F8] p-2.5 rounded border border-[#DADCE0]">
              {bellResult.explanation}
            </p>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. ENTANGLEMENT VERIFICATION */}
      {/* ========================================================================= */}
      {activeTab === 'entanglement' && entangleResult && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="bg-white border border-[#DADCE0] rounded-md p-4">
              <div className="text-[11px] font-bold text-[#5F6368] uppercase">Entanglement Status</div>
              <div className="text-base font-bold text-[#2E7D32] mt-1">
                {entangleResult.entanglement_status}
              </div>
              <div className="text-xs text-[#5F6368] mt-1">Bell State: {entangleResult.bell_state_used}</div>
            </div>

            <div className="bg-white border border-[#DADCE0] rounded-md p-4">
              <div className="text-[11px] font-bold text-[#5F6368] uppercase">Correlation Rate</div>
              <div className="text-base font-bold font-mono text-[#2457A6] mt-1">
                {entangleResult.correlation_display}
              </div>
              <div className="text-xs text-[#5F6368] mt-1">
                {entangleResult.matching_measurements} Matching / {entangleResult.total_measurements} Total Shots
              </div>
            </div>

            <div className="bg-white border border-[#DADCE0] rounded-md p-4">
              <div className="text-[11px] font-bold text-[#5F6368] uppercase">Decoherence Noise</div>
              <div className="text-base font-bold font-mono text-[#202124] mt-1">
                {(entangleNoise * 100).toFixed(2)}%
              </div>
              <div className="text-xs text-[#5F6368] mt-1">
                {entangleResult.mismatching_measurements} Uncorrelated events
              </div>
            </div>
          </div>

          <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
            <h4 className="text-xs font-bold text-[#202124] uppercase tracking-wide">Noise Sensitivity Simulation</h4>
            <div>
              <div className="flex justify-between text-xs text-[#5F6368] mb-1">
                <span>Simulated Channel Decoherence</span>
                <span className="font-mono font-bold text-[#202124]">{(entangleNoise * 100).toFixed(2)}%</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="0.05"
                step="0.001"
                value={entangleNoise}
                onChange={(e) => setEntangleNoise(parseFloat(e.target.value))}
                className="w-full accent-[#2457A6]"
              />
            </div>
            <button
              onClick={runEntanglement}
              className="px-3.5 py-1.5 bg-[#2457A6] hover:bg-[#1E4B8F] text-white text-xs font-semibold rounded cursor-pointer"
            >
              Verify Entanglement
            </button>
            <p className="text-xs text-[#5F6368]">{entangleResult.explanation}</p>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 5. TELEPORTATION & PAULI CORRECTIONS */}
      {/* ========================================================================= */}
      {activeTab === 'teleportation' && teleportResult && (
        <div className="space-y-4">
          <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-[#DADCE0] pb-3">
              <div>
                <h4 className="text-sm font-bold text-[#202124]">Quantum Teleportation & Pauli Correction</h4>
                <p className="text-xs text-[#5F6368]">
                  Transfers quantum-state information via entanglement and 2 classical bits without transporting matter.
                </p>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 bg-[#E8F5E9] text-[#2E7D32] border border-[#C8E6C9] rounded font-bold">
                Fidelity: 100.0%
              </span>
            </div>

            {/* Technical Flow Diagram */}
            <div className="p-3.5 bg-[#F5F6F8] rounded border border-[#DADCE0]">
              <div className="text-xs font-bold text-[#5F6368] uppercase tracking-wide mb-2">
                Quantum Teleportation Information Flow
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-center text-xs font-mono">
                <div className="p-2 bg-white rounded border border-[#DADCE0]">
                  <div className="font-bold text-[#202124]">Message |ψ⟩</div>
                  <div className="text-[10px] text-[#5F6368] mt-0.5">Input State</div>
                </div>
                <div className="p-2 bg-white rounded border border-[#DADCE0]">
                  <div className="font-bold text-[#2457A6]">Alice</div>
                  <div className="text-[10px] text-[#5F6368] mt-0.5">Bell Measurement</div>
                </div>
                <div className="p-2 bg-white rounded border border-[#DADCE0]">
                  <div className="font-bold text-[#202124]">Classical Bits</div>
                  <div className="text-[10px] text-[#2457A6] font-bold mt-0.5">{teleportResult.alice_measurement.bits}</div>
                </div>
                <div className="p-2 bg-white rounded border border-[#DADCE0]">
                  <div className="font-bold text-[#202124]">Pauli Gate</div>
                  <div className="text-[10px] text-[#2E7D32] font-bold mt-0.5">{teleportResult.pauli_correction.gate_symbol}</div>
                </div>
                <div className="p-2 bg-white rounded border border-[#DADCE0]">
                  <div className="font-bold text-[#2E7D32]">Bob</div>
                  <div className="text-[10px] text-[#5F6368] mt-0.5">Recovered |ψ⟩</div>
                </div>
              </div>
            </div>

            {/* Pauli Table */}
            <div>
              <div className="text-xs font-bold text-[#5F6368] uppercase tracking-wide mb-1.5">
                Pauli Correction Lookup Table for Classical Bits (b0, b1)
              </div>
              <div className="border border-[#DADCE0] rounded overflow-hidden">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="bg-[#F5F6F8] border-b border-[#DADCE0] text-[#5F6368]">
                      <th className="py-2 px-3">Bits</th>
                      <th className="py-2 px-3">Correction Gate</th>
                      <th className="py-2 px-3">Mathematical Transformation</th>
                      <th className="py-2 px-3">Active State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#DADCE0]">
                    <tr className={teleportResult.alice_measurement.bits === '00' ? 'bg-[#E8F0FE] font-bold' : ''}>
                      <td className="py-2 px-3 text-[#2457A6]">00</td>
                      <td className="py-2 px-3">Identity (I)</td>
                      <td className="py-2 px-3 text-[#5F6368]">I|ψ⟩ = |ψ⟩</td>
                      <td className="py-2 px-3">{teleportResult.alice_measurement.bits === '00' ? '● SELECTED' : '—'}</td>
                    </tr>
                    <tr className={teleportResult.alice_measurement.bits === '01' ? 'bg-[#E8F0FE] font-bold' : ''}>
                      <td className="py-2 px-3 text-[#2457A6]">01</td>
                      <td className="py-2 px-3">Pauli-X (Bit Flip)</td>
                      <td className="py-2 px-3 text-[#5F6368]">X(X|ψ⟩) = |ψ⟩</td>
                      <td className="py-2 px-3">{teleportResult.alice_measurement.bits === '01' ? '● SELECTED' : '—'}</td>
                    </tr>
                    <tr className={teleportResult.alice_measurement.bits === '10' ? 'bg-[#E8F0FE] font-bold' : ''}>
                      <td className="py-2 px-3 text-[#2457A6]">10</td>
                      <td className="py-2 px-3">Pauli-Z (Phase Flip)</td>
                      <td className="py-2 px-3 text-[#5F6368]">Z(Z|ψ⟩) = |ψ⟩</td>
                      <td className="py-2 px-3">{teleportResult.alice_measurement.bits === '10' ? '● SELECTED' : '—'}</td>
                    </tr>
                    <tr className={teleportResult.alice_measurement.bits === '11' ? 'bg-[#E8F0FE] font-bold' : ''}>
                      <td className="py-2 px-3 text-[#2457A6]">11</td>
                      <td className="py-2 px-3">Pauli-XZ (Bit + Phase Flip)</td>
                      <td className="py-2 px-3 text-[#5F6368]">Z·X(X·Z|ψ⟩) = |ψ⟩</td>
                      <td className="py-2 px-3">{teleportResult.alice_measurement.bits === '11' ? '● SELECTED' : '—'}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <button
              onClick={runTeleportation}
              disabled={loading}
              className="px-3.5 py-1.5 bg-[#2457A6] hover:bg-[#1E4B8F] text-white text-xs font-semibold rounded cursor-pointer"
            >
              Simulate Teleportation Shot
            </button>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 6. QUANTUM CHANNEL SECURITY & ATTACKS */}
      {/* ========================================================================= */}
      {activeTab === 'channel' && channelResult && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
            {[
              { id: 'NORMAL', label: 'Normal Channel', sub: 'QBER < 2.0% (Secure)' },
              { id: 'QUANTUM-EAVESDROPPING', label: 'Quantum Eavesdropping', sub: 'Entangle-and-Measure (~45%)' },
              { id: 'INTERCEPT-RESEND', label: 'Intercept-Resend', sub: 'Basis measurement (~25%)' },
              { id: 'QUANTUM-CHANNEL-MANIPULATION', label: 'Channel Manipulation', sub: 'State perturbation (~32%)' },
            ].map((m) => (
              <button
                key={m.id}
                onClick={() => {
                  setChannelMode(m.id);
                  runChannel(m.id);
                }}
                className={`p-3 rounded border text-left cursor-pointer transition ${
                  channelMode === m.id
                    ? m.id === 'NORMAL'
                      ? 'bg-[#E8F5E9] border-[#2E7D32] text-[#2E7D32] font-bold'
                      : 'bg-[#FFEBEE] border-[#C62828] text-[#C62828] font-bold'
                    : 'bg-white border-[#DADCE0] text-[#5F6368] hover:bg-[#F5F6F8]'
                }`}
              >
                <div className="text-xs font-mono">{m.label}</div>
                <div className="text-[11px] opacity-80 mt-0.5">{m.sub}</div>
              </button>
            ))}
          </div>

          <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-[#DADCE0] pb-3">
              <div>
                <h4 className="text-sm font-bold text-[#202124]">Quantum Channel Analysis</h4>
                <div className="text-xs font-mono text-[#5F6368] mt-0.5">
                  QBER = (Mismatched Bits / Total Compared Bits) × 100
                </div>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded font-mono font-bold border ${
                channelResult.qber < 0.05
                  ? 'bg-[#E8F5E9] text-[#2E7D32] border-[#C8E6C9]'
                  : 'bg-[#FFEBEE] text-[#C62828] border-[#FFCDD2]'
              }`}>
                {channelResult.channel_status}
              </span>
            </div>

            {/* Technical Parameter Table */}
            <div className="border border-[#DADCE0] rounded overflow-hidden">
              <table className="w-full text-left text-xs border-collapse font-mono">
                <thead>
                  <tr className="bg-[#F5F6F8] border-b border-[#DADCE0] text-[#5F6368]">
                    <th className="py-2 px-3">Parameter</th>
                    <th className="py-2 px-3">Result</th>
                    <th className="py-2 px-3">Standard Reference</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#DADCE0]">
                  <tr>
                    <td className="py-2 px-3 font-semibold text-[#202124]">Total Bits</td>
                    <td className="py-2 px-3">{channelResult.total_bits}</td>
                    <td className="py-2 px-3 text-[#5F6368]">1,000 Key Bits</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-semibold text-[#202124]">Matching Bits</td>
                    <td className="py-2 px-3 text-[#2E7D32]">{channelResult.matching_bits}</td>
                    <td className="py-2 px-3 text-[#5F6368]">Ideal: 1,000</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-semibold text-[#202124]">Mismatching Bits</td>
                    <td className="py-2 px-3 text-[#C62828]">{channelResult.mismatching_bits}</td>
                    <td className="py-2 px-3 text-[#5F6368]">Ideal: &le; 20</td>
                  </tr>
                  <tr className="bg-[#F5F6F8]">
                    <td className="py-2 px-3 font-bold text-[#202124]">QBER</td>
                    <td className="py-2 px-3 font-bold text-[#2457A6]">{channelResult.qber_percentage}</td>
                    <td className="py-2 px-3 font-bold text-[#5F6368]">&lt; 11.0% Safe Limit</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-semibold text-[#202124]">Channel Status</td>
                    <td className="py-2 px-3 font-bold">{channelResult.channel_status}</td>
                    <td className="py-2 px-3 text-[#5F6368]">{channelResult.qber < 0.11 ? 'Authenticated' : 'Aborted'}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Playbook */}
            <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0] space-y-2 text-xs">
              <div className="font-bold text-[#202124] uppercase tracking-wide">Incident Response Details</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <span className="font-semibold text-[#5F6368] block">First Action:</span>
                  <p className="font-mono text-[#202124] text-[11px] mt-0.5">{channelResult.first_action}</p>
                </div>
                <div>
                  <span className="font-semibold text-[#5F6368] block">Countermeasure:</span>
                  <p className="text-[#202124] text-[11px] mt-0.5">{channelResult.countermeasure}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
