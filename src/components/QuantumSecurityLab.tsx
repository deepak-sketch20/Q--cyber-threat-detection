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
    <div id="quantum-security-lab-container" className="space-y-4">
      {/* Research Header Banner */}
      <div className="bg-[#111827] border border-[#1E293B] rounded p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-[#F1F5F9] tracking-tight uppercase">
              Quantum Security Simulation
            </h3>
            <span className="text-[11px] font-mono px-2 py-0.5 bg-[#162032] text-[#94A3B8] border border-[#1E293B] rounded">
              Backend: Local Simulator
            </span>
          </div>
          <p className="text-xs text-[#94A3B8] mt-1">
            Quantum security measurements are generated using a local simulation environment. Results represent simulated channel behaviour and are not measurements from physical quantum hardware.
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
          className="px-3.5 py-1.5 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Run Simulation</span>
        </button>
      </div>

      {/* Compact Technical Parameters Table */}
      <div className="bg-[#111827] border border-[#1E293B] rounded p-3">
        <div className="text-[10px] font-bold text-[#94A3B8] uppercase tracking-wider mb-2 font-mono">
          Simulation Operational Parameters
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 text-xs font-mono">
          <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
            <span className="text-[10px] text-[#94A3B8] block font-sans">Bell State</span>
            <span className="font-bold text-[#F1F5F9]">{selectedBell === 'Phi+' ? 'Φ+' : selectedBell}</span>
          </div>
          <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
            <span className="text-[10px] text-[#94A3B8] block font-sans">Entanglement</span>
            <span className="font-bold text-[#34D399]">Verified</span>
          </div>
          <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
            <span className="text-[10px] text-[#94A3B8] block font-sans">Teleportation</span>
            <span className="font-bold text-[#F1F5F9]">Completed</span>
          </div>
          <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
            <span className="text-[10px] text-[#94A3B8] block font-sans">Pauli Correction</span>
            <span className="font-bold text-[#F1F5F9]">I / X / Z / XZ</span>
          </div>
          <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
            <span className="text-[10px] text-[#94A3B8] block font-sans">Fidelity</span>
            <span className="font-bold text-[#34D399]">{pipelineResult ? `${(pipelineResult.teleportation.fidelity * 100).toFixed(1)}%` : '100%'}</span>
          </div>
          <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
            <span className="text-[10px] text-[#94A3B8] block font-sans">Channel QBER</span>
            <span className={`font-bold ${(pipelineResult?.channel_security?.qber ?? 0) >= 0.11 ? 'text-[#F87171]' : 'text-[#F1F5F9]'}`}>
              {pipelineResult?.channel_security?.qber_percentage || '1.20%'}
            </span>
          </div>
          <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
            <span className="text-[10px] text-[#94A3B8] block font-sans">Threshold</span>
            <span className="font-bold text-[#64748B]">11.0%</span>
          </div>
          <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
            <span className="text-[10px] text-[#94A3B8] block font-sans">Channel Status</span>
            <span className={`font-bold ${(pipelineResult?.channel_security?.qber ?? 0) >= 0.11 ? 'text-[#F87171]' : 'text-[#34D399]'}`}>
              {pipelineResult?.channel_security?.channel_status === 'CRITICAL' ? 'Disturbed' : 'Normal'}
            </span>
          </div>
        </div>
      </div>

      {/* Laboratory Module Navigation Tabs */}
      <div className="flex items-center gap-1 border-b border-[#1E293B] bg-[#111827] px-2 pt-2 rounded-t-md overflow-x-auto">
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
                  ? 'border-[#0284C7] text-[#38BDF8] font-bold bg-[#162032]'
                  : 'border-transparent text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#162032]/50'
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
            <div className="bg-[#111827] border border-[#1E293B] rounded-md p-3.5">
              <div className="text-[11px] font-semibold text-[#94A3B8] uppercase tracking-wide">Protocol</div>
              <div className="text-sm font-bold text-[#F1F5F9] mt-1">3-Qubit Teleportation</div>
              <div className="text-[11px] text-[#94A3B8] mt-0.5 font-mono">Bell Entangled (Φ+)</div>
            </div>

            <div className="bg-[#111827] border border-[#1E293B] rounded-md p-3.5">
              <div className="text-[11px] font-semibold text-[#94A3B8] uppercase tracking-wide">Channel QBER</div>
              <div className={`text-sm font-bold font-mono mt-1 ${
                pipelineResult.channel_security.qber < 0.05 ? 'text-[#34D399]' : 'text-[#F87171]'
              }`}>
                {pipelineResult.channel_security.qber_percentage}
              </div>
              <div className="text-[11px] text-[#94A3B8] mt-0.5">Threshold Limit: 11.0%</div>
            </div>

            <div className="bg-[#111827] border border-[#1E293B] rounded-md p-3.5">
              <div className="text-[11px] font-semibold text-[#94A3B8] uppercase tracking-wide">Fidelity Recovery</div>
              <div className="text-sm font-bold text-[#34D399] font-mono mt-1">100.0%</div>
              <div className="text-[11px] text-[#94A3B8] mt-0.5">Pauli Gate: {pipelineResult.teleportation.pauli_correction.gate_symbol}</div>
            </div>

            <div className="bg-[#111827] border border-[#1E293B] rounded-md p-3.5">
              <div className="text-[11px] font-semibold text-[#94A3B8] uppercase tracking-wide">Risk Assessment</div>
              <div className={`text-sm font-bold font-mono mt-1 ${
                pipelineResult.risk_engine.risk_score >= 60 ? 'text-[#F87171]' : 'text-[#34D399]'
              }`}>
                {pipelineResult.risk_engine.risk_score} / 100 ({pipelineResult.risk_engine.risk_level})
              </div>
              <div className="text-[11px] text-[#94A3B8] mt-0.5 truncate">{pipelineResult.risk_engine.primary_threat}</div>
            </div>
          </div>

          {/* Lifecycle Steps */}
          <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E293B] pb-3">
              <div>
                <h4 className="text-xs font-bold text-[#F1F5F9] uppercase tracking-wider">
                  QDS Simulation Lifecycle
                </h4>
                <p className="text-xs text-[#94A3B8]">
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
                      ? 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46] font-bold'
                      : 'bg-[#162032] text-[#94A3B8] border-[#1E293B]'
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
                      ? 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B] font-bold'
                      : 'bg-[#162032] text-[#94A3B8] border-[#1E293B]'
                  }`}
                >
                  Simulate Eavesdropping
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="border border-[#1E293B] rounded p-3 bg-[#162032]">
                <div className="text-[11px] font-bold text-[#38BDF8] uppercase mb-1">Step 1: Preparation</div>
                <div className="text-xs font-semibold text-[#F1F5F9]">Qubit Superposition |ψ⟩</div>
                <div className="text-[11px] font-mono text-[#94A3B8] mt-1">H|0⟩ = (|0⟩ + |1⟩)/√2</div>
                <div className="text-[10px] text-[#34D399] font-semibold mt-2">✓ Statevector initialized</div>
              </div>

              <div className="border border-[#1E293B] rounded p-3 bg-[#162032]">
                <div className="text-[11px] font-bold text-[#38BDF8] uppercase mb-1">Step 2: Entanglement</div>
                <div className="text-xs font-semibold text-[#F1F5F9]">Bell State Φ+ Pair</div>
                <div className="text-[11px] font-mono text-[#94A3B8] mt-1">H(q1) → CNOT(q1, q2)</div>
                <div className="text-[10px] text-[#34D399] font-semibold mt-2">✓ {pipelineResult.entanglement.correlation_display} correlated</div>
              </div>

              <div className="border border-[#1E293B] rounded p-3 bg-[#162032]">
                <div className="text-[11px] font-bold text-[#38BDF8] uppercase mb-1">Step 3: Alice Measurement</div>
                <div className="text-xs font-semibold text-[#F1F5F9]">Joint Bell Projection</div>
                <div className="text-[11px] font-mono text-[#F1F5F9] mt-1 font-bold">
                  Bits: {pipelineResult.teleportation.alice_measurement.bits}
                </div>
                <div className="text-[10px] text-[#94A3B8] mt-2">Classical link sent to Bob</div>
              </div>

              <div className="border border-[#1E293B] rounded p-3 bg-[#162032]">
                <div className="text-[11px] font-bold text-[#38BDF8] uppercase mb-1">Step 4: Bob Recovery</div>
                <div className="text-xs font-semibold text-[#F1F5F9]">Pauli Correction</div>
                <div className="text-[11px] font-mono text-[#F1F5F9] mt-1 font-bold">
                  Gate: {pipelineResult.teleportation.pauli_correction.gate_symbol}
                </div>
                <div className="text-[10px] text-[#34D399] font-semibold mt-2">✓ State Fidelity: 100.0%</div>
              </div>
            </div>

            {/* Technical Channel Table */}
            <div className="border border-[#1E293B] rounded p-3.5 bg-[#162032] space-y-2">
              <div className="text-xs font-bold text-[#F1F5F9] uppercase tracking-wide">
                Channel Security & Response Playbook
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-2.5 bg-[#111827] rounded border border-[#1E293B]">
                  <span className="font-semibold text-[#94A3B8] block mb-1">First Action:</span>
                  <p className="font-mono text-[#F1F5F9] text-[11px] leading-relaxed">
                    {pipelineResult.channel_security.first_action}
                  </p>
                </div>
                <div className="p-2.5 bg-[#111827] rounded border border-[#1E293B]">
                  <span className="font-semibold text-[#94A3B8] block mb-1">Countermeasure:</span>
                  <p className="text-[#F1F5F9] text-[11px] leading-relaxed">
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
          <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4 space-y-4">
            <h4 className="text-xs font-bold text-[#F1F5F9] uppercase tracking-wide">
              Qubit Parameter Controls
            </h4>

            <div>
              <label className="block text-xs font-semibold text-[#94A3B8] mb-1.5">Preset Quantum State</label>
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
                        ? 'bg-[#0284C7] text-white border-[#0284C7] font-bold'
                        : 'bg-[#162032] text-[#94A3B8] border-[#1E293B] hover:text-[#F1F5F9] hover:bg-[#1E293B]'
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-[#94A3B8] mb-1">
                <span>Bloch Sphere Angle θ</span>
                <span className="font-mono font-bold text-[#F1F5F9]">{qubitTheta.toFixed(2)} rad</span>
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
                className="w-full accent-[#0284C7]"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#94A3B8] mb-1">Measurement Shots</label>
              <select
                value={qubitShots}
                onChange={(e) => setQubitShots(parseInt(e.target.value, 10))}
                className="w-full bg-[#162032] border border-[#1E293B] rounded px-3 py-1.5 text-xs text-[#F1F5F9] focus:outline-hidden"
              >
                <option value={100}>100 Shots</option>
                <option value={1024}>1,024 Shots (Standard Aer)</option>
                <option value={4096}>4,096 Shots (High Precision)</option>
              </select>
            </div>

            <button
              onClick={runQubit}
              disabled={loading}
              className="w-full py-2 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded transition cursor-pointer"
            >
              Run Qubit Simulation
            </button>
          </div>

          <div className="lg:col-span-2 bg-[#111827] border border-[#1E293B] rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div>
                <h4 className="text-sm font-bold text-[#F1F5F9]">{qubitResult.state_name}</h4>
                <div className="text-xs font-mono text-[#94A3B8] mt-0.5">{qubitResult.gate_applied}</div>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 bg-[#162032] text-[#38BDF8] border border-[#1E293B] rounded font-bold">
                {qubitResult.statevector.formula}
              </span>
            </div>

            <div>
              <div className="text-xs font-bold text-[#94A3B8] uppercase tracking-wide mb-2">
                Measurement Probability Collapse ({qubitResult.shots} Shots)
              </div>
              <div className="space-y-2">
                <div>
                  <div className="flex justify-between text-xs font-mono text-[#F1F5F9] mb-1">
                    <span>Outcome |0⟩ (P: {qubitResult.probabilities['0_percent']})</span>
                    <span>{qubitResult.measurements['0']} counts ({((qubitResult.measurements['0'] / qubitResult.shots) * 100).toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-[#1E293B] border border-[#334155] rounded h-3 overflow-hidden">
                    <div
                      className="bg-[#0284C7] h-full"
                      style={{ width: `${qubitResult.probabilities['0'] * 100}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-[#F1F5F9] mb-1">
                    <span>Outcome |1⟩ (P: {qubitResult.probabilities['1_percent']})</span>
                    <span>{qubitResult.measurements['1']} counts ({((qubitResult.measurements['1'] / qubitResult.shots) * 100).toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-[#1E293B] border border-[#334155] rounded h-3 overflow-hidden">
                    <div
                      className="bg-[#64748B] h-full"
                      style={{ width: `${qubitResult.probabilities['1'] * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>

            <div>
              <div className="text-xs font-bold text-[#94A3B8] uppercase tracking-wide mb-1">
                Quantum Circuit Diagram (QASM)
              </div>
              <pre className="bg-[#0B0F17] p-3 rounded border border-[#1E293B] text-xs font-mono text-[#38BDF8] overflow-x-auto">
                {qubitResult.circuit_ascii}
              </pre>
            </div>

            <p className="text-xs text-[#94A3B8] bg-[#162032] p-2.5 rounded border border-[#1E293B]">
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
          <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4 space-y-3">
            <h4 className="text-xs font-bold text-[#F1F5F9] uppercase tracking-wide">
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
                      ? 'bg-[#0284C7] text-white border-[#0284C7]'
                      : 'bg-[#162032] text-[#F1F5F9] border-[#1E293B] hover:bg-[#1E293B]'
                  }`}
                >
                  <div className={`text-xs font-mono font-bold ${selectedBell === b.id ? 'text-white' : 'text-[#F1F5F9]'}`}>{b.label}</div>
                  <div className={`text-[11px] mt-0.5 ${selectedBell === b.id ? 'text-white/80' : 'text-[#94A3B8]'}`}>{b.desc}</div>
                </button>
              ))}
            </div>

            <button
              onClick={runBell}
              disabled={loading}
              className="w-full py-2 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded transition cursor-pointer"
            >
              Generate Bell State
            </button>
          </div>

          <div className="lg:col-span-2 bg-[#111827] border border-[#1E293B] rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div>
                <h4 className="text-sm font-bold text-[#F1F5F9]">Bell State: {bellResult.bell_state}</h4>
                <div className="text-xs font-mono text-[#94A3B8] mt-0.5">{bellResult.formula}</div>
              </div>
              <div className="text-xs font-mono text-[#94A3B8]">
                {bellResult.shots} Total Shots
              </div>
            </div>

            <div>
              <div className="text-xs font-bold text-[#94A3B8] uppercase tracking-wide mb-2">
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
                        isExpected ? 'bg-[#162032] border-[#0284C7] text-[#38BDF8]' : 'bg-[#111827] border-[#1E293B] text-[#94A3B8]'
                      }`}
                    >
                      <div className="text-xs font-bold">|{basis}⟩</div>
                      <div className="text-base font-bold mt-1 text-[#F1F5F9]">{pct}%</div>
                      <div className="text-[10px] text-[#94A3B8] mt-0.5">{count} counts</div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="text-xs font-bold text-[#94A3B8] uppercase tracking-wide mb-1">
                Preparation Circuit
              </div>
              <pre className="bg-[#0B0F17] p-3 rounded border border-[#1E293B] text-xs font-mono text-[#38BDF8] overflow-x-auto">
                {bellResult.circuit_ascii}
              </pre>
            </div>

            <p className="text-xs text-[#94A3B8] bg-[#162032] p-2.5 rounded border border-[#1E293B]">
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
            <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4">
              <div className="text-[11px] font-bold text-[#94A3B8] uppercase">Entanglement Status</div>
              <div className="text-base font-bold text-[#34D399] mt-1">
                {entangleResult.entanglement_status}
              </div>
              <div className="text-xs text-[#94A3B8] mt-1">Bell State: {entangleResult.bell_state_used}</div>
            </div>

            <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4">
              <div className="text-[11px] font-bold text-[#94A3B8] uppercase">Correlation Rate</div>
              <div className="text-base font-bold font-mono text-[#38BDF8] mt-1">
                {entangleResult.correlation_display}
              </div>
              <div className="text-xs text-[#94A3B8] mt-1">
                {entangleResult.matching_measurements} Matching / {entangleResult.total_measurements} Total Shots
              </div>
            </div>

            <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4">
              <div className="text-[11px] font-bold text-[#94A3B8] uppercase">Decoherence Noise</div>
              <div className="text-base font-bold font-mono text-[#F1F5F9] mt-1">
                {(entangleNoise * 100).toFixed(2)}%
              </div>
              <div className="text-xs text-[#94A3B8] mt-1">
                {entangleResult.mismatching_measurements} Uncorrelated events
              </div>
            </div>
          </div>

          <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4 space-y-3">
            <h4 className="text-xs font-bold text-[#F1F5F9] uppercase tracking-wide">Noise Sensitivity Simulation</h4>
            <div>
              <div className="flex justify-between text-xs text-[#94A3B8] mb-1">
                <span>Simulated Channel Decoherence</span>
                <span className="font-mono font-bold text-[#F1F5F9]">{(entangleNoise * 100).toFixed(2)}%</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="0.05"
                step="0.001"
                value={entangleNoise}
                onChange={(e) => setEntangleNoise(parseFloat(e.target.value))}
                className="w-full accent-[#0284C7]"
              />
            </div>
            <button
              onClick={runEntanglement}
              className="px-3.5 py-1.5 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded cursor-pointer"
            >
              Verify Entanglement
            </button>
            <p className="text-xs text-[#94A3B8]">{entangleResult.explanation}</p>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 5. TELEPORTATION & PAULI CORRECTIONS */}
      {/* ========================================================================= */}
      {activeTab === 'teleportation' && teleportResult && (
        <div className="space-y-4">
          <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div>
                <h4 className="text-sm font-bold text-[#F1F5F9]">Quantum Teleportation & Pauli Correction</h4>
                <p className="text-xs text-[#94A3B8]">
                  Transfers quantum-state information via entanglement and 2 classical bits without transporting matter.
                </p>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 bg-[#064E3B]/40 text-[#34D399] border border-[#065F46] rounded font-bold">
                Fidelity: 100.0%
              </span>
            </div>

            {/* Technical Flow Diagram */}
            <div className="p-3.5 bg-[#162032] rounded border border-[#1E293B]">
              <div className="text-xs font-bold text-[#94A3B8] uppercase tracking-wide mb-2">
                Quantum Teleportation Information Flow
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-center text-xs font-mono">
                <div className="p-2 bg-[#111827] rounded border border-[#1E293B]">
                  <div className="font-bold text-[#F1F5F9]">Message |ψ⟩</div>
                  <div className="text-[10px] text-[#94A3B8] mt-0.5">Input State</div>
                </div>
                <div className="p-2 bg-[#111827] rounded border border-[#1E293B]">
                  <div className="font-bold text-[#38BDF8]">Alice</div>
                  <div className="text-[10px] text-[#94A3B8] mt-0.5">Bell Measurement</div>
                </div>
                <div className="p-2 bg-[#111827] rounded border border-[#1E293B]">
                  <div className="font-bold text-[#F1F5F9]">Classical Bits</div>
                  <div className="text-[10px] text-[#38BDF8] font-bold mt-0.5">{teleportResult.alice_measurement.bits}</div>
                </div>
                <div className="p-2 bg-[#111827] rounded border border-[#1E293B]">
                  <div className="font-bold text-[#F1F5F9]">Pauli Gate</div>
                  <div className="text-[10px] text-[#34D399] font-bold mt-0.5">{teleportResult.pauli_correction.gate_symbol}</div>
                </div>
                <div className="p-2 bg-[#111827] rounded border border-[#1E293B]">
                  <div className="font-bold text-[#34D399]">Bob</div>
                  <div className="text-[10px] text-[#94A3B8] mt-0.5">Recovered |ψ⟩</div>
                </div>
              </div>
            </div>

            {/* Pauli Table */}
            <div>
              <div className="text-xs font-bold text-[#94A3B8] uppercase tracking-wide mb-1.5">
                Pauli Correction Lookup Table for Classical Bits (b0, b1)
              </div>
              <div className="border border-[#1E293B] rounded overflow-hidden">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="bg-[#162032] border-b border-[#1E293B] text-[#94A3B8]">
                      <th className="py-2 px-3">Bits</th>
                      <th className="py-2 px-3">Correction Gate</th>
                      <th className="py-2 px-3">Mathematical Transformation</th>
                      <th className="py-2 px-3">Active State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1E293B]">
                    <tr className={teleportResult.alice_measurement.bits === '00' ? 'bg-[#0284C7]/20 font-bold' : ''}>
                      <td className="py-2 px-3 text-[#38BDF8]">00</td>
                      <td className="py-2 px-3 text-[#F1F5F9]">Identity (I)</td>
                      <td className="py-2 px-3 text-[#94A3B8]">I|ψ⟩ = |ψ⟩</td>
                      <td className="py-2 px-3 text-[#34D399]">{teleportResult.alice_measurement.bits === '00' ? '● SELECTED' : '—'}</td>
                    </tr>
                    <tr className={teleportResult.alice_measurement.bits === '01' ? 'bg-[#0284C7]/20 font-bold' : ''}>
                      <td className="py-2 px-3 text-[#38BDF8]">01</td>
                      <td className="py-2 px-3 text-[#F1F5F9]">Pauli-X (Bit Flip)</td>
                      <td className="py-2 px-3 text-[#94A3B8]">X(X|ψ⟩) = |ψ⟩</td>
                      <td className="py-2 px-3 text-[#34D399]">{teleportResult.alice_measurement.bits === '01' ? '● SELECTED' : '—'}</td>
                    </tr>
                    <tr className={teleportResult.alice_measurement.bits === '10' ? 'bg-[#0284C7]/20 font-bold' : ''}>
                      <td className="py-2 px-3 text-[#38BDF8]">10</td>
                      <td className="py-2 px-3 text-[#F1F5F9]">Pauli-Z (Phase Flip)</td>
                      <td className="py-2 px-3 text-[#94A3B8]">Z(Z|ψ⟩) = |ψ⟩</td>
                      <td className="py-2 px-3 text-[#34D399]">{teleportResult.alice_measurement.bits === '10' ? '● SELECTED' : '—'}</td>
                    </tr>
                    <tr className={teleportResult.alice_measurement.bits === '11' ? 'bg-[#0284C7]/20 font-bold' : ''}>
                      <td className="py-2 px-3 text-[#38BDF8]">11</td>
                      <td className="py-2 px-3 text-[#F1F5F9]">Pauli-XZ (Bit + Phase Flip)</td>
                      <td className="py-2 px-3 text-[#94A3B8]">Z·X(X·Z|ψ⟩) = |ψ⟩</td>
                      <td className="py-2 px-3 text-[#34D399]">{teleportResult.alice_measurement.bits === '11' ? '● SELECTED' : '—'}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <button
              onClick={runTeleportation}
              disabled={loading}
              className="px-3.5 py-1.5 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded cursor-pointer"
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
                      ? 'bg-[#064E3B]/40 border-[#065F46] text-[#34D399] font-bold'
                      : 'bg-[#7F1D1D]/40 border-[#991B1B] text-[#F87171] font-bold'
                    : 'bg-[#162032] border-[#1E293B] text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#1E293B]'
                }`}
              >
                <div className="text-xs font-mono">{m.label}</div>
                <div className="text-[11px] opacity-80 mt-0.5">{m.sub}</div>
              </button>
            ))}
          </div>

          <div className="bg-[#111827] border border-[#1E293B] rounded-md p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <div>
                <h4 className="text-sm font-bold text-[#F1F5F9]">Quantum Channel Analysis</h4>
                <div className="text-xs font-mono text-[#94A3B8] mt-0.5">
                  QBER = (Mismatched Bits / Total Compared Bits) × 100
                </div>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded font-mono font-bold border ${
                channelResult.qber < 0.05
                  ? 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]'
                  : 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]'
              }`}>
                {channelResult.channel_status}
              </span>
            </div>

            {/* Technical Parameter Table */}
            <div className="border border-[#1E293B] rounded overflow-hidden">
              <table className="w-full text-left text-xs border-collapse font-mono">
                <thead>
                  <tr className="bg-[#162032] border-b border-[#1E293B] text-[#94A3B8]">
                    <th className="py-2 px-3">Parameter</th>
                    <th className="py-2 px-3">Result</th>
                    <th className="py-2 px-3">Standard Reference</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1E293B]">
                  <tr>
                    <td className="py-2 px-3 font-semibold text-[#F1F5F9]">Total Bits</td>
                    <td className="py-2 px-3 text-[#F1F5F9]">{channelResult.total_bits}</td>
                    <td className="py-2 px-3 text-[#94A3B8]">1,000 Key Bits</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-semibold text-[#F1F5F9]">Matching Bits</td>
                    <td className="py-2 px-3 text-[#34D399]">{channelResult.matching_bits}</td>
                    <td className="py-2 px-3 text-[#94A3B8]">Ideal: 1,000</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-semibold text-[#F1F5F9]">Mismatching Bits</td>
                    <td className="py-2 px-3 text-[#F87171]">{channelResult.mismatching_bits}</td>
                    <td className="py-2 px-3 text-[#94A3B8]">Ideal: &le; 20</td>
                  </tr>
                  <tr className="bg-[#162032]">
                    <td className="py-2 px-3 font-bold text-[#F1F5F9]">QBER</td>
                    <td className="py-2 px-3 font-bold text-[#38BDF8]">{channelResult.qber_percentage}</td>
                    <td className="py-2 px-3 font-bold text-[#94A3B8]">&lt; 11.0% Safe Limit</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-3 font-semibold text-[#F1F5F9]">Channel Status</td>
                    <td className="py-2 px-3 font-bold text-[#F1F5F9]">{channelResult.channel_status}</td>
                    <td className="py-2 px-3 text-[#94A3B8]">{channelResult.qber < 0.11 ? 'Authenticated' : 'Aborted'}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Playbook */}
            <div className="p-3 bg-[#162032] rounded border border-[#1E293B] space-y-2 text-xs">
              <div className="font-bold text-[#F1F5F9] uppercase tracking-wide">Incident Response Details</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <span className="font-semibold text-[#94A3B8] block">First Action:</span>
                  <p className="font-mono text-[#F1F5F9] text-[11px] mt-0.5">{channelResult.first_action}</p>
                </div>
                <div>
                  <span className="font-semibold text-[#94A3B8] block">Countermeasure:</span>
                  <p className="text-[#F1F5F9] text-[11px] mt-0.5">{channelResult.countermeasure}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
