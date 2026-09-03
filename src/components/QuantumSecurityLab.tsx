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
  Sparkles,
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
  CompleteQdsResult,
  ProjectiveMeasurementResult
} from '../qdsSimulatorEngine';

export const QuantumSecurityLab: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'qubit' | 'bell' | 'entanglement' | 'teleportation' | 'channel' | 'pipeline'>('pipeline');
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

  // Initial runs
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
      // Call local TypeScript engine or API fallback
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
    <div id="quantum-security-lab-container" className="space-y-6">
      {/* Simulation Notice Banner */}
      <div id="qds-simulation-banner" className="bg-slate-900 border border-cyan-500/30 rounded-xl p-4 text-slate-200 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-lg shadow-cyan-950/20">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-950/80 border border-cyan-500/40 rounded-lg text-cyan-400">
            <Atom className="w-6 h-6 animate-spin-slow" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-white tracking-wide text-sm sm:text-base">
                Quantum Security Lab & QDS Simulator
              </h3>
              <span className="px-2 py-0.5 text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-full">
                SIMULATION-BASED
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Simulated quantum operations using statevector mathematics & Qiskit-equivalent circuits. Transfers quantum-state information via entanglement & classical communication (matter is not transported).
            </p>
          </div>
        </div>
        <button
          id="btn-re-simulate-all"
          onClick={() => {
            runPipeline();
            runQubit();
            runBell();
            runEntanglement();
            runTeleportation();
            runChannel();
          }}
          disabled={loading}
          className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium rounded-lg flex items-center gap-2 transition-all shadow-md shrink-0 disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Run Full Quantum Suite
        </button>
      </div>

      {/* Lab Station Navigation Tabs */}
      <div id="qds-lab-tabs" className="flex items-center gap-1.5 overflow-x-auto pb-2 border-b border-slate-700/60 no-scrollbar">
        {[
          { id: 'pipeline', label: 'End-to-End QDS Pipeline', icon: Layers, badge: 'Full Flow' },
          { id: 'qubit', label: 'Qubit Lab', icon: Atom, badge: 'Hadamard' },
          { id: 'bell', label: 'Bell State Generator', icon: Network, badge: '4 States' },
          { id: 'entanglement', label: 'Entanglement Verification', icon: Zap, badge: 'Correlations' },
          { id: 'teleportation', label: 'Teleportation & Pauli', icon: Radio, badge: '3-Qubit Protocol' },
          { id: 'channel', label: 'Channel Security & Attacks', icon: ShieldAlert, badge: 'QBER & Eavesdropping' },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`tab-btn-${tab.id}`}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2.5 rounded-lg text-xs font-medium flex items-center gap-2 whitespace-nowrap transition-all ${
                isActive
                  ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
              <span>{tab.label}</span>
              <span
                className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono ${
                  isActive ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-500'
                }`}
              >
                {tab.badge}
              </span>
            </button>
          );
        })}
      </div>

      {/* ========================================================================= */}
      {/* 1. END-TO-END PIPELINE VIEW */}
      {/* ========================================================================= */}
      {activeTab === 'pipeline' && pipelineResult && (
        <div id="qds-pipeline-view" className="space-y-6 animate-fadeIn">
          {/* Executive Posture Bar */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-4">
              <div className="text-xs font-mono text-slate-400 flex items-center justify-between">
                <span>SIMULATED WORKFLOW</span>
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              </div>
              <div className="text-lg font-bold text-white mt-1">3-Qubit QDS Teleport</div>
              <div className="text-xs text-cyan-400 mt-0.5">Entanglement & Pauli Correction</div>
            </div>

            <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-4">
              <div className="text-xs font-mono text-slate-400 flex items-center justify-between">
                <span>CHANNEL STATUS</span>
                <Radio className="w-3.5 h-3.5 text-blue-400" />
              </div>
              <div className="text-lg font-bold text-white mt-1 flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${pipelineResult.channel_security.qber < 0.05 ? 'bg-emerald-400' : 'bg-red-400 animate-pulse'}`} />
                {pipelineResult.channel_security.threshold_category}
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                QBER: <span className="font-mono text-white font-bold">{pipelineResult.channel_security.qber_percentage}</span> (Limit: 11.0%)
              </div>
            </div>

            <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-4">
              <div className="text-xs font-mono text-slate-400 flex items-center justify-between">
                <span>FIDELITY RECOVERY</span>
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              </div>
              <div className="text-lg font-bold text-emerald-400 mt-1 font-mono">100.0%</div>
              <div className="text-xs text-slate-400 mt-0.5">Pauli Gate: {pipelineResult.teleportation.pauli_correction.gate_symbol}</div>
            </div>

            <div className={`border rounded-xl p-4 ${
              pipelineResult.risk_engine.risk_level === 'CRITICAL'
                ? 'bg-red-950/40 border-red-500/40 text-red-200'
                : pipelineResult.risk_engine.risk_level === 'HIGH'
                ? 'bg-amber-950/40 border-amber-500/40 text-amber-200'
                : 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
            }`}>
              <div className="text-xs font-mono flex items-center justify-between opacity-80">
                <span>RISK ENGINE POSTURE</span>
                <ShieldAlert className="w-3.5 h-3.5" />
              </div>
              <div className="text-lg font-bold mt-1 font-mono">{pipelineResult.risk_engine.risk_score} / 100 ({pipelineResult.risk_engine.risk_level})</div>
              <div className="text-xs truncate mt-0.5">{pipelineResult.risk_engine.primary_threat}</div>
            </div>
          </div>

          {/* 7-Step Interactive Pipeline Flow Visualizer */}
          <div className="bg-slate-800/90 border border-slate-700 rounded-xl p-5 shadow-sm">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div>
                <h4 className="text-sm font-semibold text-white">Quantum Digital Signature (QDS) Simulation Lifecycle</h4>
                <p className="text-xs text-slate-400">Step-by-step statevector propagation and classical reconciliation workflow</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setChannelMode('NORMAL');
                    runPipeline('NORMAL');
                  }}
                  className={`px-2.5 py-1 text-xs rounded border transition-all ${
                    channelMode === 'NORMAL' ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50' : 'bg-slate-900 text-slate-400 border-slate-700'
                  }`}
                >
                  Normal Channel
                </button>
                <button
                  onClick={() => {
                    setChannelMode('QUANTUM-EAVESDROPPING');
                    runPipeline('QUANTUM-EAVESDROPPING');
                  }}
                  className={`px-2.5 py-1 text-xs rounded border transition-all ${
                    channelMode === 'QUANTUM-EAVESDROPPING' ? 'bg-red-950/80 text-red-300 border-red-500/50' : 'bg-slate-900 text-slate-400 border-slate-700'
                  }`}
                >
                  Simulate Eavesdropping
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {/* Step 1 */}
              <div className="bg-slate-900/90 border border-slate-700/60 rounded-lg p-3.5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between text-xs text-cyan-400 font-mono mb-1.5">
                    <span>STEP 1: PREPARATION</span>
                    <Atom className="w-3.5 h-3.5" />
                  </div>
                  <div className="text-xs font-semibold text-white">Qubit Superposition |ψ⟩</div>
                  <div className="text-[11px] text-slate-400 font-mono mt-1">
                    H|0⟩ = (|0⟩ + |1⟩)/√2
                  </div>
                </div>
                <div className="mt-2.5 pt-2 border-t border-slate-800 text-[11px] text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Statevector initialized
                </div>
              </div>

              {/* Step 2 */}
              <div className="bg-slate-900/90 border border-slate-700/60 rounded-lg p-3.5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between text-xs text-blue-400 font-mono mb-1.5">
                    <span>STEP 2: ENTANGLEMENT</span>
                    <Zap className="w-3.5 h-3.5" />
                  </div>
                  <div className="text-xs font-semibold text-white">Bell State Φ+ Pair</div>
                  <div className="text-[11px] text-slate-400 font-mono mt-1">
                    H(q1) → CNOT(q1, q2)
                  </div>
                </div>
                <div className="mt-2.5 pt-2 border-t border-slate-800 text-[11px] text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> {pipelineResult.entanglement.correlation_display} Correlated
                </div>
              </div>

              {/* Step 3 */}
              <div className="bg-slate-900/90 border border-slate-700/60 rounded-lg p-3.5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between text-xs text-purple-400 font-mono mb-1.5">
                    <span>STEP 3: ALICE MEASUREMENT</span>
                    <Radio className="w-3.5 h-3.5" />
                  </div>
                  <div className="text-xs font-semibold text-white">Joint Bell Measurement</div>
                  <div className="text-[11px] text-slate-400 font-mono mt-1">
                    Bits: <span className="text-yellow-300 font-bold">{pipelineResult.teleportation.alice_measurement.bits}</span> (b0, b1)
                  </div>
                </div>
                <div className="mt-2.5 pt-2 border-t border-slate-800 text-[11px] text-purple-300 flex items-center gap-1">
                  <Send className="w-3 h-3" /> Classical link transmission
                </div>
              </div>

              {/* Step 4 */}
              <div className="bg-slate-900/90 border border-slate-700/60 rounded-lg p-3.5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between text-xs text-emerald-400 font-mono mb-1.5">
                    <span>STEP 4: BOB RECOVERY</span>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  </div>
                  <div className="text-xs font-semibold text-white">Pauli Correction</div>
                  <div className="text-[11px] text-slate-400 font-mono mt-1">
                    Applied Gate: <span className="text-emerald-300 font-bold">{pipelineResult.teleportation.pauli_correction.gate_symbol}</span>
                  </div>
                </div>
                <div className="mt-2.5 pt-2 border-t border-slate-800 text-[11px] text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> State Fidelity: 100.0%
                </div>
              </div>
            </div>

            {/* Step 5-7 Channel Analysis & Threat Mitigation */}
            <div className="mt-4 p-4 bg-slate-900/90 border border-slate-700 rounded-lg">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-cyan-400 font-bold">AUTOMATED THREAT CORRELATION & FIRST ACTION PLAYBOOK</span>
                <span className={`text-xs px-2 py-0.5 rounded font-mono font-bold ${
                  pipelineResult.channel_security.qber >= 0.11
                    ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                }`}>
                  {pipelineResult.channel_security.threat_detected}
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                <div className="space-y-1">
                  <div className="text-xs text-slate-400 font-medium">Immediate First Response:</div>
                  <div className="text-xs text-white bg-slate-800/80 p-2.5 rounded border border-slate-700 font-mono">
                    {pipelineResult.channel_security.first_action}
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="text-xs text-slate-400 font-medium">Recommended Cryptographic Countermeasure:</div>
                  <div className="text-xs text-slate-300 bg-slate-800/80 p-2.5 rounded border border-slate-700">
                    {pipelineResult.channel_security.countermeasure}
                  </div>
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
        <div id="qds-qubit-view" className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fadeIn">
          {/* Controls */}
          <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-5 space-y-4">
            <h4 className="text-sm font-semibold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Qubit State Controls
            </h4>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Preset Quantum State</label>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { id: '0', label: '|0⟩ Ground' },
                  { id: '1', label: '|1⟩ Excited (X)' },
                  { id: 'superposition', label: '|+⟩ Equal Superposition (H)' },
                  { id: 'minus', label: '|-⟩ Phase State (HX)' },
                ].map((s) => (
                  <button
                    key={s.id}
                    onClick={() => {
                      setQubitState(s.id);
                      setTimeout(runQubit, 50);
                    }}
                    className={`px-3 py-2 text-xs rounded-lg text-left transition-all font-mono ${
                      qubitState === s.id
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/50'
                        : 'bg-slate-900/80 text-slate-400 hover:text-white border border-slate-800'
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1">
                <span>Bloch Sphere Angle θ</span>
                <span className="font-mono text-cyan-400">{qubitTheta.toFixed(2)} rad</span>
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
                className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1">
                <span>Measurement Shots</span>
                <span className="font-mono text-cyan-400">{qubitShots}</span>
              </div>
              <select
                value={qubitShots}
                onChange={(e) => setQubitShots(parseInt(e.target.value, 10))}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white"
              >
                <option value={100}>100 Shots (Fast sample)</option>
                <option value={1024}>1,024 Shots (Standard Aer Simulator)</option>
                <option value={4096}>4,096 Shots (High precision)</option>
              </select>
            </div>

            <button
              onClick={runQubit}
              disabled={loading}
              className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg transition-all"
            >
              Simulate Qubit Execution
            </button>
          </div>

          {/* Statevector & Circuit */}
          <div className="lg:col-span-2 bg-slate-800/80 border border-slate-700/80 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/60 pb-3">
              <div>
                <h4 className="text-sm font-semibold text-white">{qubitResult.state_name}</h4>
                <div className="text-xs text-cyan-400 font-mono mt-0.5">{qubitResult.gate_applied}</div>
              </div>
              <span className="text-xs font-mono px-2.5 py-1 bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-full">
                {qubitResult.statevector.formula}
              </span>
            </div>

            {/* Measurement Distributions */}
            <div>
              <div className="text-xs font-medium text-slate-300 mb-2">Measurement Probability Collapse (Over {qubitResult.shots} Shots)</div>
              <div className="space-y-2">
                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-300 mb-1">
                    <span>Outcome |0⟩ (Prob: {qubitResult.probabilities['0_percent']})</span>
                    <span>{qubitResult.measurements['0']} counts ({qubitResult.measurements.ratio_0 * 100}%)</span>
                  </div>
                  <div className="w-full bg-slate-900 rounded-full h-3 overflow-hidden border border-slate-800">
                    <div
                      className="bg-cyan-500 h-full transition-all duration-500"
                      style={{ width: `${qubitResult.probabilities['0'] * 100}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-300 mb-1">
                    <span>Outcome |1⟩ (Prob: {qubitResult.probabilities['1_percent']})</span>
                    <span>{qubitResult.measurements['1']} counts ({qubitResult.measurements.ratio_1 * 100}%)</span>
                  </div>
                  <div className="w-full bg-slate-900 rounded-full h-3 overflow-hidden border border-slate-800">
                    <div
                      className="bg-blue-500 h-full transition-all duration-500"
                      style={{ width: `${qubitResult.probabilities['1'] * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* ASCII Circuit Representation */}
            <div>
              <div className="text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                <span>Quantum Circuit Model (QASM / ASCII representation)</span>
              </div>
              <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto leading-relaxed">
                {qubitResult.circuit_ascii}
              </pre>
            </div>

            <p className="text-xs text-slate-400 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              {qubitResult.explanation}
            </p>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. BELL STATE GENERATOR */}
      {/* ========================================================================= */}
      {activeTab === 'bell' && bellResult && (
        <div id="qds-bell-view" className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fadeIn">
          {/* Controls */}
          <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-5 space-y-4">
            <h4 className="text-sm font-semibold text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Maximally Entangled Bell Basis
            </h4>

            <div className="space-y-2">
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
                  className={`w-full p-3 text-left rounded-lg transition-all border ${
                    selectedBell === b.id
                      ? 'bg-cyan-950 text-cyan-200 border-cyan-500/50 shadow-sm'
                      : 'bg-slate-900/70 text-slate-400 border-slate-800 hover:text-white'
                  }`}
                >
                  <div className="text-xs font-bold font-mono text-white">{b.label}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">{b.desc}</div>
                </button>
              ))}
            </div>

            <button
              onClick={runBell}
              disabled={loading}
              className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg transition-all"
            >
              Generate Bell Pair State
            </button>
          </div>

          {/* Results & Qiskit code */}
          <div className="lg:col-span-2 bg-slate-800/80 border border-slate-700/80 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/60 pb-3">
              <div>
                <h4 className="text-sm font-semibold text-white">Bell State: {bellResult.bell_state}</h4>
                <div className="text-xs text-cyan-400 font-mono mt-0.5">{bellResult.formula}</div>
              </div>
              <div className="text-xs text-slate-400 font-mono">
                {bellResult.shots} Total Shots
              </div>
            </div>

            {/* 4-State Probability Histogram */}
            <div>
              <div className="text-xs font-medium text-slate-300 mb-2">2-Qubit Computational Basis Measurement Distribution</div>
              <div className="grid grid-cols-4 gap-2">
                {['00', '01', '10', '11'].map((basis) => {
                  const count = bellResult.measurement_counts[basis] || 0;
                  const pct = ((count / bellResult.shots) * 100).toFixed(1);
                  const isExpected = (bellResult.ideal_probabilities[basis] || 0) > 0;
                  return (
                    <div
                      key={basis}
                      className={`p-3 rounded-lg border text-center font-mono ${
                        isExpected ? 'bg-slate-900 border-cyan-500/40 text-cyan-300' : 'bg-slate-900/50 border-slate-800 text-slate-500'
                      }`}
                    >
                      <div className="text-sm font-bold">|{basis}⟩</div>
                      <div className="text-xs font-semibold mt-1">{pct}%</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">{count} counts</div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Preparation Steps & ASCII Circuit */}
            <div>
              <div className="text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                <span>Preparation Circuit & QASM Model</span>
              </div>
              <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto leading-relaxed">
                {bellResult.circuit_ascii}
              </pre>
            </div>

            <p className="text-xs text-slate-400 bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              {bellResult.explanation}
            </p>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. ENTANGLEMENT VERIFICATION */}
      {/* ========================================================================= */}
      {activeTab === 'entanglement' && entangleResult && (
        <div id="qds-entanglement-view" className="space-y-6 animate-fadeIn">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-5">
              <div className="text-xs font-mono text-slate-400">ENTANGLEMENT STATUS</div>
              <div className="text-xl font-bold text-emerald-400 mt-1 flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5" />
                {entangleResult.entanglement_status}
              </div>
              <div className="text-xs text-slate-400 mt-1">Bell State: {entangleResult.bell_state_used}</div>
            </div>

            <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-5">
              <div className="text-xs font-mono text-slate-400">CORRELATION PERCENTAGE</div>
              <div className="text-xl font-bold text-cyan-400 mt-1 font-mono">
                {entangleResult.correlation_display}
              </div>
              <div className="text-xs text-slate-400 mt-1">
                {entangleResult.matching_measurements} Matching / {entangleResult.total_measurements} Total Shots
              </div>
            </div>

            <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-5">
              <div className="text-xs font-mono text-slate-400">DECOHERENCE NOISE</div>
              <div className="text-xl font-bold text-slate-200 mt-1 font-mono">
                {(entangleNoise * 100).toFixed(2)}%
              </div>
              <div className="text-xs text-slate-400 mt-1">
                {entangleResult.mismatching_measurements} Uncorrelated events
              </div>
            </div>
          </div>

          <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-5 space-y-4">
            <h4 className="text-sm font-semibold text-white">Interactive Noise Sensitivity Adjuster</h4>
            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1">
                <span>Simulated Channel Decoherence & Physical Noise</span>
                <span className="font-mono text-cyan-400">{(entangleNoise * 100).toFixed(2)}%</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="0.05"
                step="0.001"
                value={entangleNoise}
                onChange={(e) => setEntangleNoise(parseFloat(e.target.value))}
                className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>
            <button
              onClick={runEntanglement}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg"
            >
              Verify Quantum Entanglement Correlation
            </button>
            <p className="text-xs text-slate-400">{entangleResult.explanation}</p>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 5. TELEPORTATION & PAULI CORRECTIONS */}
      {/* ========================================================================= */}
      {activeTab === 'teleportation' && teleportResult && (
        <div id="qds-teleportation-view" className="space-y-6 animate-fadeIn">
          <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/60 pb-3">
              <div>
                <h4 className="text-sm font-semibold text-white">Quantum Teleportation & Unitary Pauli Correction</h4>
                <p className="text-xs text-slate-400">
                  Transfers quantum-state information using entanglement and 2 classical bits. (Matter is not transported).
                </p>
              </div>
              <span className="text-xs font-mono px-3 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full">
                Fidelity: 100.0%
              </span>
            </div>

            {/* Protocol Steps Box */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800">
                <div className="text-[11px] font-mono text-cyan-400">1. INPUT STATE |ψ⟩</div>
                <div className="text-xs font-semibold text-white mt-1">{teleportResult.original_message_state.description}</div>
                <div className="text-[11px] font-mono text-slate-400 mt-1">
                  α={teleportResult.original_message_state.alpha}, β={teleportResult.original_message_state.beta}
                </div>
              </div>

              <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800">
                <div className="text-[11px] font-mono text-purple-400">2. ALICE MEASUREMENT</div>
                <div className="text-xs font-semibold text-white mt-1">Classical Bits: {teleportResult.alice_measurement.bits}</div>
                <div className="text-[11px] font-mono text-slate-400 mt-1">
                  q0={teleportResult.alice_measurement.q0_bit}, q1={teleportResult.alice_measurement.q1_bit}
                </div>
              </div>

              <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800">
                <div className="text-[11px] font-mono text-yellow-400">3. PAULI CORRECTION</div>
                <div className="text-xs font-semibold text-white mt-1">{teleportResult.pauli_correction.correction_gate}</div>
                <div className="text-[11px] font-mono text-slate-400 mt-1">
                  Gate: {teleportResult.pauli_correction.gate_symbol}
                </div>
              </div>

              <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800">
                <div className="text-[11px] font-mono text-emerald-400">4. BOB RECOVERED |ψ⟩</div>
                <div className="text-xs font-semibold text-white mt-1">{teleportResult.bob_recovered_state.state_formula}</div>
                <div className="text-[11px] font-mono text-slate-400 mt-1">
                  Match: TRUE (100.0%)
                </div>
              </div>
            </div>

            {/* Pauli Matrix Lookup Map */}
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
              <div className="text-xs font-mono text-slate-300 mb-2">Pauli Correction Lookup Table for Classical Bits (b0, b1):</div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                <div className={`p-2.5 rounded border ${teleportResult.alice_measurement.bits === '00' ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200' : 'bg-slate-900 border-slate-800 text-slate-400'}`}>
                  <div className="font-bold">Bits: 00</div>
                  <div className="text-[11px] text-slate-300">Gate: Identity (I)</div>
                  <div className="text-[10px] text-slate-400">I|ψ⟩ = |ψ⟩</div>
                </div>
                <div className={`p-2.5 rounded border ${teleportResult.alice_measurement.bits === '01' ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200' : 'bg-slate-900 border-slate-800 text-slate-400'}`}>
                  <div className="font-bold">Bits: 01</div>
                  <div className="text-[11px] text-slate-300">Gate: Pauli-X</div>
                  <div className="text-[10px] text-slate-400">X(X|ψ⟩) = |ψ⟩</div>
                </div>
                <div className={`p-2.5 rounded border ${teleportResult.alice_measurement.bits === '10' ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200' : 'bg-slate-900 border-slate-800 text-slate-400'}`}>
                  <div className="font-bold">Bits: 10</div>
                  <div className="text-[11px] text-slate-300">Gate: Pauli-Z</div>
                  <div className="text-[10px] text-slate-400">Z(Z|ψ⟩) = |ψ⟩</div>
                </div>
                <div className={`p-2.5 rounded border ${teleportResult.alice_measurement.bits === '11' ? 'bg-cyan-950/80 border-cyan-500 text-cyan-200' : 'bg-slate-900 border-slate-800 text-slate-400'}`}>
                  <div className="font-bold">Bits: 11</div>
                  <div className="text-[11px] text-slate-300">Gate: Pauli-XZ</div>
                  <div className="text-[10px] text-slate-400">Z·X(X·Z|ψ⟩) = |ψ⟩</div>
                </div>
              </div>
            </div>

            <button
              onClick={runTeleportation}
              disabled={loading}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded-lg"
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
        <div id="qds-channel-view" className="space-y-6 animate-fadeIn">
          {/* Attack Mode Switcher */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
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
                className={`p-3.5 rounded-xl text-left border transition-all ${
                  channelMode === m.id
                    ? m.id === 'NORMAL'
                      ? 'bg-emerald-950/80 border-emerald-500/60 text-emerald-200 shadow-md'
                      : 'bg-red-950/80 border-red-500/60 text-red-200 shadow-md'
                    : 'bg-slate-800/80 border-slate-700 text-slate-400 hover:text-white'
                }`}
              >
                <div className="text-xs font-bold font-mono">{m.label}</div>
                <div className="text-[11px] text-slate-400 mt-1">{m.sub}</div>
              </button>
            ))}
          </div>

          {/* QBER Metrics & Threat Posture */}
          <div className="bg-slate-800/80 border border-slate-700/80 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-700/60 pb-3">
              <div>
                <h4 className="text-sm font-semibold text-white">Quantum Bit Error Rate (QBER) Security Assessment</h4>
                <div className="text-xs text-cyan-400 font-mono mt-0.5">
                  QBER Formula: (Mismatched Bits / Total Compared Bits) × 100
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs px-2.5 py-1 rounded font-mono font-bold ${
                  channelResult.qber < 0.05
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-red-500/20 text-red-300 border border-red-500/40'
                }`}>
                  {channelResult.channel_status}
                </span>
              </div>
            </div>

            {/* QBER Gauge & Thresholds */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-slate-900 rounded-lg border border-slate-800">
                <div className="text-xs text-slate-400 font-mono">CALCULATED QBER</div>
                <div className="text-2xl font-bold font-mono text-white mt-1">{channelResult.qber_percentage}</div>
                <div className="text-xs text-slate-400 mt-1">
                  {channelResult.mismatching_bits} mismatches in {channelResult.total_bits} bits
                </div>
              </div>

              <div className="p-4 bg-slate-900 rounded-lg border border-slate-800">
                <div className="text-xs text-slate-400 font-mono">EAVESDROPPING PROBABILITY</div>
                <div className="text-2xl font-bold font-mono text-red-400 mt-1">
                  {channelResult.estimated_eavesdropping_probability}
                </div>
                <div className="text-xs text-slate-400 mt-1">Calculated physical disturbance</div>
              </div>

              <div className="p-4 bg-slate-900 rounded-lg border border-slate-800">
                <div className="text-xs text-slate-400 font-mono">QDS SECURITY BOUND</div>
                <div className="text-sm font-bold text-cyan-300 mt-2 font-mono">
                  Limit: &lt; 11.00% QBER
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  {channelResult.qber < 0.11 ? '✓ Within Secure Threshold' : '✗ Bound Exceeded'}
                </div>
              </div>
            </div>

            {/* First Action Playbook */}
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-cyan-400">
                <ShieldAlert className="w-4 h-4" />
                <span>CYBERSECURITY INCIDENT RESPONSE & IMMEDIATE ACTION</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="text-xs text-slate-400 font-medium">First Immediate Action:</div>
                  <div className="text-xs text-white bg-slate-900 p-2.5 rounded border border-slate-800 font-mono mt-1">
                    {channelResult.first_action}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-slate-400 font-medium">Mitigation Countermeasure:</div>
                  <div className="text-xs text-slate-300 bg-slate-900 p-2.5 rounded border border-slate-800 mt-1">
                    {channelResult.countermeasure}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
