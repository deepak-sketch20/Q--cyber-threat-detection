import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  FileText,
  Upload,
  Zap,
  Activity,
  CheckCircle,
  AlertTriangle,
  Lock,
  Copy,
  Check,
  RefreshCw,
  Terminal,
  Printer,
  Download,
  Atom,
  BarChart3,
  FileCode,
  Info,
  Server,
  Layers,
  Cpu,
  Database,
  KeyRound,
  ExternalLink,
  ChevronRight,
  Filter,
  Search,
  Mail,
  XCircle,
  HelpCircle
} from 'lucide-react';
import { AnalysisResponse, SecurityLog } from './types';
import { SAMPLE_DATASETS, analyzeSecurityText, computeSha256 } from './analyzerEngine';
import { CbomModal } from './components/CbomModal';
import { CertificateModal } from './components/CertificateModal';
import { ExecutiveForensicAlert } from './components/ExecutiveForensicAlert';
import { QuantumSecurityLab } from './components/QuantumSecurityLab';

export default function App() {
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [activeSampleId, setActiveSampleId] = useState<string>('test_1_secure.txt');
  const [referenceHashInput, setReferenceHashInput] = useState<string>('');
  const [mode, setMode] = useState<string>('Automatic Detection');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [copiedLogHash, setCopiedLogHash] = useState<string | null>(null);
  const [logFilter, setLogFilter] = useState<'ALL' | 'ALERT' | 'WARNING' | 'VALID'>('ALL');
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');
  const [currentTime, setCurrentTime] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'dashboard' | 'file-analysis' | 'quantum-lab' | 'threat-detection' | 'logs' | 'guide'>('dashboard');
  const [cbomOpen, setCbomOpen] = useState<boolean>(false);
  const [certModalOpen, setCertModalOpen] = useState<boolean>(false);
  const [emailAlertModalOpen, setEmailAlertModalOpen] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Live time ticker
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Initial load with Test 1 (Secure file)
  useEffect(() => {
    handleLoadSample('test_1_secure.txt');
  }, []);

  const handleLoadSample = async (sampleId: string, currentMode = mode, refHash = referenceHashInput) => {
    setLoading(true);
    setSelectedFile(null);
    setActiveSampleId(sampleId);
    try {
      const sample = SAMPLE_DATASETS[sampleId];
      if (!sample) return;

      const hash = await computeSha256(sample.content);
      const fileBytes = new TextEncoder().encode(sample.content).length;

      // Try server API first, fallback to local engine
      try {
        const formData = new FormData();
        formData.append('sample_id', sampleId);
        formData.append('attack_mode', currentMode);
        if (refHash) formData.append('reference_hash', refHash);

        const res = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        if (res.ok) {
          const json = await res.json();
          setData(json);
          setLoading(false);
          return;
        }
      } catch {
        // Local fallback
      }

      const result = analyzeSecurityText(sample.content, sampleId, fileBytes, hash, currentMode, refHash);
      setData(result);
    } catch (err) {
      console.error('Failed to load sample:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file: File, currentMode = mode, refHash = referenceHashInput) => {
    setLoading(true);
    setSelectedFile(file);
    setActiveSampleId('');
    try {
      const fileBuffer = await file.arrayBuffer();
      const text = new TextDecoder('utf-8').decode(fileBuffer);
      const hash = await computeSha256(fileBuffer);

      try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('attack_mode', currentMode);
        if (refHash) formData.append('reference_hash', refHash);

        const res = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        if (res.ok) {
          const json = await res.json();
          setData(json);
          setLoading(false);
          return;
        }
      } catch {
        // Fallback
      }

      const result = analyzeSecurityText(text, file.name, file.size, hash, currentMode, refHash);
      setData(result);
    } catch (err) {
      console.error('Failed to analyze uploaded file:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleModeChange = (newMode: string) => {
    setMode(newMode);
    if (selectedFile) {
      handleFileUpload(selectedFile, newMode);
    } else if (activeSampleId) {
      handleLoadSample(activeSampleId, newMode);
    } else if (data?.file?.filename && SAMPLE_DATASETS[data.file.filename]) {
      handleLoadSample(data.file.filename, newMode);
    }
  };

  const handleCopyHash = () => {
    if (data?.file.sha256) {
      navigator.clipboard.writeText(data.file.sha256);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const handleCopyLogHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedLogHash(hash);
    setTimeout(() => setCopiedLogHash(null), 2000);
  };

  const handleCopyAllLogs = () => {
    if (!data?.logs) return;
    const text = (data.logs || []).map(l => `[${l.time}] [${l.status}] ${l.event} | Hash: ${l.event_hash || ''}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedLogHash('ALL_LOGS_COPIED');
    setTimeout(() => setCopiedLogHash(null), 2000);
  };

  const handleExportJSON = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `qds_security_report_${data.case_id || Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportLogs = () => {
    if (!data?.logs) return;
    const text = (data.logs || []).map(l => `[${l.time}] [${l.status}] ${l.event} | Hash: ${l.event_hash || ''}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `qds_audit_trail_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredLogs = (data?.logs || []).filter(log => {
    if (logFilter === 'ALERT' && log.status !== 'ALERT' && log.status !== 'ACTION_REQUIRED') return false;
    if (logFilter === 'WARNING' && log.status !== 'WARNING') return false;
    if (logFilter === 'VALID' && (log.status === 'ALERT' || log.status === 'ACTION_REQUIRED' || log.status === 'WARNING')) return false;
    if (logSearchQuery.trim()) {
      const q = logSearchQuery.toLowerCase();
      return (
        log.event.toLowerCase().includes(q) ||
        (log.event_hash && log.event_hash.toLowerCase().includes(q)) ||
        log.status.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const isAttack = data?.threat?.status === 'ATTACK DETECTED';
  const riskScore = data?.threat?.risk_score ?? 0;
  const riskLevel = data?.threat?.risk ?? 'LOW';

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return '#C62828';
    if (score >= 50) return '#B26A00';
    return '#2E7D32';
  };

  return (
    <div className="min-h-screen bg-[#F5F6F8] text-[#202124] flex flex-col justify-between">
      {/* 1. Header */}
      <div>
        <header className="bg-white border-b border-[#DADCE0]">
          <div className="max-w-[1200px] mx-auto px-4 py-3.5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <h1 className="text-lg md:text-xl font-bold tracking-tight text-[#202124]">
                  QUANTUM DIGITAL SIGNATURE SECURITY ANALYZER
                </h1>
                <p className="text-xs text-[#5F6368] mt-0.5">
                  Simulation-Based Security Research Prototype &bull; Department of Computer Science &amp; Engineering
                </p>
              </div>

              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded bg-[#F5F6F8] border border-[#DADCE0] text-[#202124]">
                  <span className="w-2 h-2 rounded-full bg-[#2E7D32]"></span>
                  <span>System Status: Online</span>
                </div>
                <div className="text-xs font-mono text-[#5F6368] hidden sm:block">
                  {currentTime}
                </div>
              </div>
            </div>

            {/* Subtle technical metadata bar */}
            <div className="mt-2.5 pt-2 border-t border-[#DADCE0] text-[11px] font-mono text-[#5F6368] flex flex-wrap items-center gap-x-3 gap-y-1">
              <span>Prototype Version: 1.0</span>
              <span>&bull;</span>
              <span>Simulation Engine: Qiskit Aer</span>
              <span>&bull;</span>
              <span>Hash Algorithm: SHA-256</span>
              <span>&bull;</span>
              <span>Analysis Mode: {mode}</span>
              <span>&bull;</span>
              <span>Quantum Backend: Statevector Simulator</span>
            </div>
          </div>
        </header>

        {/* 2. Navigation Bar */}
        <nav className="bg-white border-b border-[#DADCE0] sticky top-0 z-40">
          <div className="max-w-[1200px] mx-auto px-4 flex items-center justify-between overflow-x-auto">
            <div className="flex items-center gap-1">
              {[
                { id: 'dashboard', label: 'Dashboard' },
                { id: 'file-analysis', label: 'File Analysis' },
                { id: 'quantum-lab', label: 'Quantum Security' },
                { id: 'threat-detection', label: 'Threat Detection' },
                { id: 'logs', label: 'Security Logs' },
                { id: 'guide', label: 'Lab Guide' },
              ].map((tab) => {
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`px-3.5 py-2.5 text-xs font-medium border-b-2 transition cursor-pointer -mb-[1px] whitespace-nowrap ${
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

            {/* Quick action utility buttons */}
            <div className="flex items-center gap-1.5 py-1.5 pl-2">
              <button
                onClick={() => setCbomOpen(true)}
                className="px-2.5 py-1 text-xs rounded border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] font-medium flex items-center gap-1 cursor-pointer"
                title="View CycloneDX Cryptography Bill of Materials"
              >
                <FileCode className="w-3.5 h-3.5 text-[#2457A6]" />
                <span className="hidden sm:inline">CBOM Inspector</span>
              </button>
              <button
                onClick={() => setCertModalOpen(true)}
                className="px-2.5 py-1 text-xs rounded border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] font-medium flex items-center gap-1 cursor-pointer"
                title="Inspect X.509 PKI Public Key Certificate"
              >
                <Lock className="w-3.5 h-3.5 text-[#2E7D32]" />
                <span className="hidden sm:inline">X.509 PKI</span>
              </button>
              <button
                onClick={() => setEmailAlertModalOpen(true)}
                className="px-2.5 py-1 text-xs rounded border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] font-medium flex items-center gap-1 cursor-pointer"
                title="Open Executive Forensic Email Alert Modal"
              >
                <Mail className="w-3.5 h-3.5 text-[#C62828]" />
                <span className="hidden sm:inline">Email Alert</span>
              </button>
            </div>
          </div>
        </nav>

        {/* 3. 1-Click Test Scenarios Bar */}
        <div className="bg-white border-b border-[#DADCE0] py-2">
          <div className="max-w-[1200px] mx-auto px-4">
            <div className="flex items-center gap-2 overflow-x-auto no-scrollbar text-xs">
              <span className="text-[11px] font-bold text-[#5F6368] uppercase shrink-0">
                1-Click Scenarios:
              </span>
              {[
                { id: 'test_1_secure.txt', label: '1: Secure' },
                { id: 'test_2_replay_attack.txt', label: '2: Replay' },
                { id: 'test_3_forgery_attack.txt', label: '3: Forgery' },
                { id: 'test_4_impersonation.txt', label: '4: Impersonation' },
                { id: 'test_5_channel_tampering.txt', label: '5: Tampering' },
                { id: 'test_6_quantum_eavesdropping.txt', label: '6: Eavesdropping' },
                { id: 'test_7_multiple_threats.txt', label: '7: Multi-Threat' },
                { id: 'test_8_dilithium_pqc.txt', label: '8: Dilithium PQC' },
                { id: 'test_9_rsa2048_pki_pass.txt', label: '9: RSA PKI Pass' },
                { id: 'test_10_ecdsa_pki_fail.txt', label: '10: ECDSA PKI Fail' },
              ].map((s) => (
                <button
                  key={s.id}
                  onClick={() => handleLoadSample(s.id)}
                  disabled={loading}
                  className={`px-2 py-1 rounded border text-[11px] font-mono whitespace-nowrap cursor-pointer transition ${
                    data?.file.filename === s.id
                      ? 'bg-[#2457A6] text-white border-[#2457A6] font-bold'
                      : 'bg-[#F5F6F8] text-[#202124] border-[#DADCE0] hover:bg-[#E8EAED]'
                  }`}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* 4. Main Container */}
        <main className="max-w-[1200px] mx-auto px-4 py-5 space-y-5">
          {/* Top Summary 4-Panel Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Panel 1: File Status */}
            <div className="bg-white border border-[#DADCE0] rounded-md p-3.5 transition-all">
              <div className="text-[11px] font-bold uppercase text-[#5F6368]">File Status</div>
              <div className={`text-base font-bold font-mono mt-1 ${
                isAttack || data?.signature?.hash_mismatch ? 'text-[#C62828]' : 'text-[#2E7D32]'
              }`}>
                {isAttack || data?.signature?.hash_mismatch ? 'COMPROMISED' : 'SECURE'}
              </div>
              <div className="text-[11px] text-[#5F6368] mt-0.5 truncate font-mono" title={data?.file?.filename}>
                {data?.file?.filename || 'No file selected'} ({data?.file?.file_size || '0 B'})
              </div>
            </div>

            {/* Panel 2: Signature Status */}
            <div className="bg-white border border-[#DADCE0] rounded-md p-3.5 transition-all">
              <div className="text-[11px] font-bold uppercase text-[#5F6368]">Signature Status</div>
              <div className={`text-base font-bold font-mono mt-1 ${
                data?.signature?.signature_status === 'VALID' || data?.cryptographic_verification?.is_verified ? 'text-[#2E7D32]' : 'text-[#C62828]'
              }`}>
                {data?.signature?.signature_status || 'NOT AVAILABLE'}
              </div>
              <div className="text-[11px] text-[#5F6368] mt-0.5 truncate">
                {data?.cryptographic_verification?.algorithm_detected || data?.signature?.signature_algorithm || 'ECDSA / RSA-2048'}
              </div>
            </div>

            {/* Panel 3: Threat Status */}
            <div className="bg-white border border-[#DADCE0] rounded-md p-3.5 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase text-[#5F6368]">Threat Status</span>
                {loading && (
                  <span className="text-[10px] text-[#2457A6] font-mono animate-pulse font-semibold">ANALYZING...</span>
                )}
              </div>
              <div className={`text-base font-bold font-mono mt-1 ${
                isAttack ? 'text-[#C62828]' : 'text-[#2E7D32]'
              }`}>
                {isAttack ? 'ATTACK DETECTED' : 'SECURE'}
              </div>
              <div className="text-[11px] text-[#5F6368] mt-0.5 truncate" title={isAttack ? data?.threat?.detected_threat : 'No threat detected'}>
                {isAttack ? (data?.threat?.detected_threat || 'Threat Detected') : 'Intact • Verified Channel'}
              </div>
            </div>

            {/* Panel 4: Risk Score */}
            <div className="bg-white border border-[#DADCE0] rounded-md p-3.5 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase text-[#5F6368]">Risk Score</span>
                <span className={`text-xs font-bold font-mono px-1.5 py-0.2 rounded border ${
                  riskScore >= 80
                    ? 'bg-[#FFEBEE] text-[#C62828] border-[#FFCDD2]'
                    : riskScore >= 50
                    ? 'bg-[#FFF3E0] text-[#B26A00] border-[#FFE0B2]'
                    : 'bg-[#E8F5E9] text-[#2E7D32] border-[#C8E6C9]'
                }`}>
                  {riskLevel}
                </span>
              </div>
              <div className="text-base font-bold font-mono mt-1 text-[#202124]">
                {riskScore} / 100
              </div>
              {/* Horizontal Progress Bar */}
              <div className="w-full bg-[#F5F6F8] border border-[#DADCE0] rounded-full h-2 mt-1.5 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-300"
                  style={{
                    width: `${riskScore}%`,
                    backgroundColor: getRiskScoreColor(riskScore)
                  }}
                />
              </div>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* TAB: DASHBOARD VIEW */}
          {/* ========================================================================= */}
          {activeTab === 'dashboard' && data && (
            <div className="space-y-5">
              {/* 2-Column Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
                {/* Left Column: File Ingestion & Cryptography (5 cols) */}
                <div className="lg:col-span-5 space-y-4">
                  {/* File Upload Panel */}
                  <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                    <div className="border-b border-[#DADCE0] pb-2">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                        Digital Signature File Ingestion
                      </h3>
                      <p className="text-[11px] text-[#5F6368]">
                        Select or drop a signed artifact for automated analysis
                      </p>
                    </div>

                    <div
                      onClick={() => fileInputRef.current?.click()}
                      onDragOver={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        setIsDragging(true);
                      }}
                      onDragEnter={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        setIsDragging(true);
                      }}
                      onDragLeave={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        setIsDragging(false);
                      }}
                      onDrop={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        setIsDragging(false);
                        if (e.dataTransfer.files?.[0]) {
                          handleFileUpload(e.dataTransfer.files[0]);
                        }
                      }}
                      className={`border-2 border-dashed rounded p-4 text-center cursor-pointer transition ${
                        isDragging
                          ? 'border-[#2457A6] bg-[#E8F0FE]'
                          : 'border-[#DADCE0] hover:border-[#2457A6] bg-[#F5F6F8]'
                      }`}
                    >
                      <input
                        ref={fileInputRef}
                        type="file"
                        onChange={(e) => {
                          if (e.target.files?.[0]) {
                            handleFileUpload(e.target.files[0]);
                            e.target.value = '';
                          }
                        }}
                        className="hidden"
                      />
                      <Upload className="w-5 h-5 mx-auto text-[#5F6368] mb-1" />
                      <div className="text-xs font-semibold text-[#202124]">
                        {selectedFile ? `Selected: ${selectedFile.name}` : 'Click to select file or drag & drop'}
                      </div>
                      <div className="text-[11px] text-[#5F6368] mt-0.5">
                        Supports .txt, .json, .pem, .sig, .bin
                      </div>
                    </div>

                    {/* Mode & Reference Digest */}
                    <div className="space-y-2 text-xs">
                      <div>
                        <label className="block text-[11px] font-semibold text-[#5F6368] mb-1">
                          Threat Detection Mode
                        </label>
                        <select
                          value={mode}
                          onChange={(e) => handleModeChange(e.target.value)}
                          className="w-full bg-white border border-[#DADCE0] rounded px-2.5 py-1.5 text-xs text-[#202124]"
                        >
                          <option value="Automatic Detection">Automatic Detection (All Vectors)</option>
                          <option value="Signature Integrity Only">Signature Integrity Only</option>
                          <option value="Quantum Channel Analysis">Quantum Channel Analysis</option>
                          <option value="Replay Attack Verification">Replay Attack Verification</option>
                          <option value="Forgery Detection">Forgery Detection</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-[11px] font-semibold text-[#5F6368] mb-1">
                          Optional Reference SHA-256 Digest
                        </label>
                        <input
                          type="text"
                          value={referenceHashInput}
                          onChange={(e) => setReferenceHashInput(e.target.value)}
                          placeholder="e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                          className="w-full bg-white border border-[#DADCE0] rounded px-2.5 py-1.5 text-xs font-mono text-[#202124]"
                        />
                      </div>

                      <div className="flex gap-2 pt-1">
                        <button
                          onClick={() => {
                            if (selectedFile) handleFileUpload(selectedFile);
                            else handleLoadSample('test_1_secure.txt');
                          }}
                          disabled={loading}
                          className="flex-1 py-1.5 bg-[#2457A6] hover:bg-[#1E4B8F] text-white text-xs font-semibold rounded cursor-pointer transition disabled:opacity-50"
                        >
                          {loading ? 'Analyzing...' : 'Analyze File'}
                        </button>
                        <button
                          onClick={() => {
                            setSelectedFile(null);
                            setReferenceHashInput('');
                            handleLoadSample('test_1_secure.txt');
                          }}
                          className="px-3 py-1.5 bg-white border border-[#DADCE0] hover:bg-[#F5F6F8] text-[#202124] text-xs font-medium rounded cursor-pointer transition"
                        >
                          Reset
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Cryptographic Layer Panel */}
                  <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-[#DADCE0] pb-2">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                        Cryptographic Verification Layer
                      </h3>
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded border border-[#DADCE0] bg-[#F5F6F8] text-[#5F6368]">
                        RFC 5280 PKI
                      </span>
                    </div>

                    <div className="space-y-1.5 text-xs font-mono">
                      <div className="flex justify-between py-1 border-b border-[#DADCE0]">
                        <span className="text-[#5F6368]">Algorithm:</span>
                        <span className="font-bold text-[#202124]">
                          {data.cryptographic_verification?.algorithm_detected || data.signature.signature_algorithm}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#DADCE0]">
                        <span className="text-[#5F6368]">Key Size:</span>
                        <span className="text-[#202124]">
                          {data.cryptographic_verification?.key_size_bits || 2048} bits
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#DADCE0]">
                        <span className="text-[#5F6368]">Shor's Quantum Impact:</span>
                        <span className="font-bold text-[#B26A00]">
                          {data.cryptographic_verification?.vulnerable_to_shors ? 'Vulnerable (O(n³))' : 'Quantum-Resistant'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-[#DADCE0]">
                        <span className="text-[#5F6368]">NIST Standard:</span>
                        <span className="text-[#202124]">
                          {data.cryptographic_verification?.nist_standard_status || 'FIPS 186-5'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1">
                        <span className="text-[#5F6368]">Signer DN:</span>
                        <span className="text-[#2457A6] truncate max-w-[200px]" title={data.signature.signer_information}>
                          {data.signature.signer_information}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right Column: Prominent Threat Analysis (7 cols) */}
                <div className="lg:col-span-7 space-y-4">
                  {/* Threat Analysis Report Card */}
                  <div className={`bg-white border rounded-md p-4 space-y-3.5 ${
                    isAttack ? 'border-[#C62828]' : 'border-[#2E7D32]'
                  }`}>
                    {/* Header */}
                    <div className="flex items-center justify-between border-b border-[#DADCE0] pb-2.5">
                      <div className="flex items-center gap-2">
                        <div className={`w-6 h-6 rounded flex items-center justify-center text-white ${
                          isAttack ? 'bg-[#C62828]' : 'bg-[#2E7D32]'
                        }`}>
                          {isAttack ? <ShieldAlert className="w-3.5 h-3.5" /> : <ShieldCheck className="w-3.5 h-3.5" />}
                        </div>
                        <div>
                          <h3 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                            Security Threat Analysis Report
                          </h3>
                          <span className="text-[11px] text-[#5F6368] font-mono">
                            Case {data.case_id} &bull; Engine Confidence: {data.threat.confidence}%
                          </span>
                        </div>
                      </div>

                      <span className={`px-2 py-0.5 rounded text-xs font-bold font-mono border uppercase ${
                        isAttack ? 'bg-[#FFEBEE] text-[#C62828] border-[#FFCDD2]' : 'bg-[#E8F5E9] text-[#2E7D32] border-[#C8E6C9]'
                      }`}>
                        {data.threat.status}
                      </span>
                    </div>

                    {/* Threat Details Grid */}
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="p-2.5 bg-[#F5F6F8] rounded border border-[#DADCE0]">
                        <span className="text-[10px] font-bold text-[#5F6368] uppercase block">Detected Threat</span>
                        <span className="font-bold text-[#202124] text-xs font-mono mt-0.5 block truncate">
                          {data.threat.detected_threat}
                        </span>
                      </div>
                      <div className="p-2.5 bg-[#F5F6F8] rounded border border-[#DADCE0]">
                        <span className="text-[10px] font-bold text-[#5F6368] uppercase block">Threat Category</span>
                        <span className="font-bold text-[#202124] text-xs font-mono mt-0.5 block truncate">
                          {data.threat.threat_category}
                        </span>
                      </div>
                    </div>

                    {/* Why was it detected? */}
                    <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0] space-y-1">
                      <span className="text-xs font-bold text-[#202124] uppercase tracking-wide block">
                        Detection Rationale / Trigger Reason
                      </span>
                      <p className="text-xs text-[#202124] leading-relaxed">
                        {data.threat.reason}
                      </p>
                    </div>

                    {/* Evidence List */}
                    <div className="space-y-1">
                      <span className="text-xs font-bold text-[#5F6368] uppercase tracking-wide block">
                        Observed Cryptographic Evidence ({(data.threat?.evidence || []).length})
                      </span>
                      <div className="space-y-1">
                        {(data.threat?.evidence || []).map((item, idx) => (
                          <div key={idx} className="flex items-start gap-2 text-xs font-mono p-1.5 bg-[#F5F6F8] rounded border border-[#DADCE0]">
                            <span className="text-[#2457A6] font-bold">{idx + 1}.</span>
                            <span className="text-[#202124]">{item}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Immediate Response & Countermeasure */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 pt-1 text-xs">
                      <div className="p-2.5 rounded border border-[#DADCE0] bg-[#FFF3E0]">
                        <span className="font-bold text-[#B26A00] block mb-1 uppercase text-[11px]">
                          First Action to Overcome
                        </span>
                        <p className="text-[#202124] text-[11px] leading-relaxed font-mono">
                          {data.threat.first_action || 'Quarantine file and alert the security operations team.'}
                        </p>
                      </div>

                      <div className="p-2.5 rounded border border-[#DADCE0] bg-[#E8F5E9]">
                        <span className="font-bold text-[#2E7D32] block mb-1 uppercase text-[11px]">
                          Preventative Countermeasure
                        </span>
                        <p className="text-[#202124] text-[11px] leading-relaxed">
                          {data.threat.recommendation || 'Transition to Post-Quantum Digital Signatures (FIPS 204 ML-DSA).'}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Executive Alert Trigger Panel */}
                  <ExecutiveForensicAlert
                    data={data}
                    isOpen={emailAlertModalOpen}
                    onOpenChange={setEmailAlertModalOpen}
                  />
                </div>
              </div>

              {/* Security Logs Section (Console Style) */}
              <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#DADCE0] pb-2.5">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-[#2457A6]" />
                    <h3 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                      Tamper-Evident Security Audit Logs
                    </h3>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded border border-[#DADCE0] bg-[#F5F6F8] text-[#5F6368]">
                      Chained SHA-256 Ledger
                    </span>
                  </div>

                  {/* Filter & Action Buttons */}
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {(['ALL', 'ALERT', 'WARNING', 'VALID'] as const).map((f) => (
                      <button
                        key={f}
                        onClick={() => setLogFilter(f)}
                        className={`px-2 py-0.5 rounded text-[11px] font-medium border cursor-pointer ${
                          logFilter === f
                            ? 'bg-[#2457A6] text-white border-[#2457A6] font-bold'
                            : 'bg-white text-[#5F6368] border-[#DADCE0] hover:bg-[#F5F6F8]'
                        }`}
                      >
                        {f}
                      </button>
                    ))}
                    <button
                      onClick={handleCopyAllLogs}
                      className="px-2 py-0.5 rounded text-[11px] font-medium border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] flex items-center gap-1 cursor-pointer"
                    >
                      <Copy className="w-3 h-3 text-[#5F6368]" />
                      <span>{copiedLogHash === 'ALL_LOGS_COPIED' ? 'Copied' : 'Copy All'}</span>
                    </button>
                    <button
                      onClick={handleExportLogs}
                      className="px-2 py-0.5 rounded text-[11px] font-medium border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] flex items-center gap-1 cursor-pointer"
                    >
                      <Download className="w-3 h-3 text-[#5F6368]" />
                      <span>Export</span>
                    </button>
                  </div>
                </div>

                {/* Search Bar */}
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-[#5F6368]" />
                  <input
                    type="text"
                    value={logSearchQuery}
                    onChange={(e) => setLogSearchQuery(e.target.value)}
                    placeholder="Search logs by event, status, or hash..."
                    className="w-full bg-[#F5F6F8] border border-[#DADCE0] rounded pl-8 pr-3 py-1.5 text-xs font-mono text-[#202124] focus:outline-hidden focus:border-[#2457A6]"
                  />
                </div>

                {/* Console Log Area */}
                <div className="bg-[#F5F6F8] border border-[#DADCE0] rounded p-3 font-mono text-xs max-h-64 overflow-y-auto space-y-1.5">
                  {filteredLogs.length === 0 ? (
                    <div className="text-center py-4 text-[#5F6368]">No log entries matching filter</div>
                  ) : (
                    filteredLogs.map((log, i) => (
                      <div key={i} className="flex items-start justify-between gap-2 border-b border-[#DADCE0]/60 pb-1 last:border-b-0">
                        <div className="flex items-start gap-2">
                          <span className="text-[#5F6368] shrink-0">{log.time}</span>
                          <span className={`px-1 rounded text-[10px] font-bold shrink-0 ${
                            log.status === 'ALERT' || log.status === 'ACTION_REQUIRED'
                              ? 'bg-[#FFEBEE] text-[#C62828]'
                              : log.status === 'WARNING'
                              ? 'bg-[#FFF3E0] text-[#B26A00]'
                              : 'bg-[#E8F5E9] text-[#2E7D32]'
                          }`}>
                            {log.status}
                          </span>
                          <span className="text-[#202124]">{log.event}</span>
                        </div>
                        {log.event_hash && (
                          <button
                            onClick={() => handleCopyLogHash(log.event_hash!)}
                            className="text-[10px] text-[#5F6368] hover:text-[#2457A6] shrink-0 font-mono"
                            title="Copy event hash"
                          >
                            {copiedLogHash === log.event_hash ? 'Copied' : `${log.event_hash.substring(0, 8)}...`}
                          </button>
                        )}
                      </div>
                    ))
                  )}
                  <div ref={logEndRef} />
                </div>
              </div>

              {/* 8-Vector Attack Matrix */}
              <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#DADCE0] pb-2.5">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                      Attack Scenario Analysis Matrix
                    </h3>
                    <p className="text-[11px] text-[#5F6368]">
                      Evaluation across 8 primary cryptographic and quantum attack vectors
                    </p>
                  </div>
                  <button
                    onClick={handleExportJSON}
                    className="px-2.5 py-1 text-xs font-medium rounded border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] flex items-center gap-1 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-[#2457A6]" />
                    <span>Download JSON Matrix</span>
                  </button>
                </div>

                <div className="border border-[#DADCE0] rounded overflow-hidden">
                  <table className="w-full text-left text-xs border-collapse font-mono">
                    <thead>
                      <tr className="bg-[#F5F6F8] border-b border-[#DADCE0] text-[#5F6368] font-sans font-bold">
                        <th className="py-2 px-3">Vector</th>
                        <th className="py-2 px-3">Status</th>
                        <th className="py-2 px-3">Risk Level</th>
                        <th className="py-2 px-3">Score</th>
                        <th className="py-2 px-3">Detection Rationale</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#DADCE0] text-[11px]">
                      {(data.attack_matrix || []).map((row, idx) => (
                        <tr key={idx} className={row.status === 'ATTACK DETECTED' ? 'bg-[#FFEBEE]/30' : 'hover:bg-[#F5F6F8]'}>
                          <td className="py-2 px-3 font-semibold text-[#202124] font-sans">{row.vector_name}</td>
                          <td className="py-2 px-3">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                              row.status === 'ATTACK DETECTED'
                                ? 'bg-[#FFEBEE] text-[#C62828] border-[#FFCDD2]'
                                : 'bg-[#E8F5E9] text-[#2E7D32] border-[#C8E6C9]'
                            }`}>
                              {row.status}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-[#5F6368]">{row.risk_level}</td>
                          <td className="py-2 px-3 font-bold text-[#202124]">{row.score}</td>
                          <td className="py-2 px-3 text-[#5F6368] font-sans truncate max-w-xs" title={row.detection_notes}>
                            {row.detection_notes}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB: FILE ANALYSIS FOCUSED VIEW */}
          {/* ========================================================================= */}
          {activeTab === 'file-analysis' && data && (
            <div className="space-y-4">
              <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                <h3 className="text-sm font-bold text-[#202124]">Digital Signature File Ingestion &amp; Verification</h3>
                <p className="text-xs text-[#5F6368]">
                  Upload target document, raw payload, or PKCS#7 / CMS signed artifact for byte-level inspection.
                </p>

                <div
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    setIsDragging(true);
                  }}
                  onDragEnter={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    setIsDragging(true);
                  }}
                  onDragLeave={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    setIsDragging(false);
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    setIsDragging(false);
                    if (e.dataTransfer.files?.[0]) {
                      handleFileUpload(e.dataTransfer.files[0]);
                    }
                  }}
                  className={`border-2 border-dashed rounded p-6 text-center cursor-pointer transition ${
                    isDragging
                      ? 'border-[#2457A6] bg-[#E8F0FE]'
                      : 'border-[#DADCE0] hover:border-[#2457A6] bg-[#F5F6F8]'
                  }`}
                >
                  <Upload className="w-6 h-6 mx-auto text-[#5F6368] mb-1.5" />
                  <div className="text-xs font-bold text-[#202124]">
                    {selectedFile ? `Selected: ${selectedFile.name}` : 'Choose a file to analyze'}
                  </div>
                  <div className="text-[11px] text-[#5F6368] mt-0.5">Click to browse or drag &amp; drop file here</div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block font-semibold text-[#5F6368] mb-1">Detection Mode</label>
                    <select
                      value={mode}
                      onChange={(e) => handleModeChange(e.target.value)}
                      className="w-full bg-white border border-[#DADCE0] rounded px-2.5 py-1.5 text-xs text-[#202124]"
                    >
                      <option value="Automatic Detection">Automatic Detection (All Vectors)</option>
                      <option value="Signature Integrity Only">Signature Integrity Only</option>
                      <option value="Quantum Channel Analysis">Quantum Channel Analysis</option>
                      <option value="Replay Attack Verification">Replay Attack Verification</option>
                      <option value="Forgery Detection">Forgery Detection</option>
                    </select>
                  </div>
                  <div>
                    <label className="block font-semibold text-[#5F6368] mb-1">Optional Reference SHA-256 Digest</label>
                    <input
                      type="text"
                      value={referenceHashInput}
                      onChange={(e) => setReferenceHashInput(e.target.value)}
                      placeholder="Expected SHA-256 hex string..."
                      className="w-full bg-white border border-[#DADCE0] rounded px-2.5 py-1.5 text-xs font-mono text-[#202124]"
                    />
                  </div>
                </div>

                <button
                  onClick={() => {
                    if (selectedFile) handleFileUpload(selectedFile);
                    else handleLoadSample('test_1_secure.txt');
                  }}
                  disabled={loading}
                  className="px-4 py-2 bg-[#2457A6] hover:bg-[#1E4B8F] text-white text-xs font-semibold rounded cursor-pointer"
                >
                  {loading ? 'Analyzing File...' : 'Run Analysis'}
                </button>
              </div>

              {/* Active File Details */}
              <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-[#202124]">Current File Metadata</h4>
                <div className="border border-[#DADCE0] rounded overflow-hidden">
                  <table className="w-full text-left text-xs border-collapse font-mono">
                    <tbody className="divide-y divide-[#DADCE0]">
                      <tr>
                        <td className="py-2 px-3 font-semibold text-[#5F6368] bg-[#F5F6F8] w-1/4">Filename</td>
                        <td className="py-2 px-3 text-[#202124]">{data.file.filename}</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-3 font-semibold text-[#5F6368] bg-[#F5F6F8]">File Size</td>
                        <td className="py-2 px-3 text-[#202124]">{data.file.file_size}</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-3 font-semibold text-[#5F6368] bg-[#F5F6F8]">SHA-256 Digest</td>
                        <td className="py-2 px-3 text-[#202124] truncate">{data.file.sha256}</td>
                      </tr>
                      <tr>
                        <td className="py-2 px-3 font-semibold text-[#5F6368] bg-[#F5F6F8]">Upload Timestamp</td>
                        <td className="py-2 px-3 text-[#202124]">{data.file.upload_time}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB: QUANTUM SECURITY LAB */}
          {/* ========================================================================= */}
          {activeTab === 'quantum-lab' && (
            <QuantumSecurityLab />
          )}

          {/* ========================================================================= */}
          {/* TAB: THREAT DETECTION REPORT */}
          {/* ========================================================================= */}
          {activeTab === 'threat-detection' && data && (
            <div className="space-y-4">
              {/* Detailed Threat Report */}
              <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-4">
                <div className="flex items-center justify-between border-b border-[#DADCE0] pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-[#202124]">Security Threat Assessment</h3>
                    <p className="text-xs text-[#5F6368]">
                      Comprehensive rule-based heuristics, signature integrity, and replay cache evaluation
                    </p>
                  </div>
                  <span className={`px-2.5 py-1 rounded text-xs font-bold font-mono border ${
                    isAttack ? 'bg-[#FFEBEE] text-[#C62828] border-[#FFCDD2]' : 'bg-[#E8F5E9] text-[#2E7D32] border-[#C8E6C9]'
                  }`}>
                    {data.threat.status} ({data.threat.risk} RISK)
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0]">
                    <span className="font-bold text-[#5F6368] block uppercase text-[10px]">Threat Type</span>
                    <span className="font-bold text-[#202124] text-xs font-mono mt-1 block">{data.threat.detected_threat}</span>
                  </div>
                  <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0]">
                    <span className="font-bold text-[#5F6368] block uppercase text-[10px]">Category</span>
                    <span className="font-bold text-[#202124] text-xs font-mono mt-1 block">{data.threat.threat_category}</span>
                  </div>
                  <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0]">
                    <span className="font-bold text-[#5F6368] block uppercase text-[10px]">Risk Score</span>
                    <span className="font-bold text-[#202124] text-xs font-mono mt-1 block">{data.threat.risk_score} / 100</span>
                  </div>
                </div>

                <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0] space-y-1 text-xs">
                  <span className="font-bold text-[#202124] uppercase">Detailed Detection Rationale:</span>
                  <p className="text-[#202124] leading-relaxed">{data.threat.reason}</p>
                </div>

                <div className="space-y-2 text-xs">
                  <span className="font-bold text-[#5F6368] uppercase">Evidence Indicators:</span>
                  <div className="space-y-1 font-mono">
                    {(data.threat?.evidence || []).map((e, idx) => (
                      <div key={idx} className="p-2 bg-[#F5F6F8] rounded border border-[#DADCE0] flex items-start gap-2">
                        <span className="text-[#2457A6] font-bold">{idx + 1}.</span>
                        <span>{e}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* 8-Vector Attack Matrix */}
              <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                  8-Vector Attack Scenario Matrix
                </h4>
                <div className="border border-[#DADCE0] rounded overflow-hidden">
                  <table className="w-full text-left text-xs border-collapse font-mono">
                    <thead>
                      <tr className="bg-[#F5F6F8] border-b border-[#DADCE0] text-[#5F6368] font-sans font-bold">
                        <th className="py-2 px-3">Vector</th>
                        <th className="py-2 px-3">Status</th>
                        <th className="py-2 px-3">Risk Level</th>
                        <th className="py-2 px-3">Score</th>
                        <th className="py-2 px-3">Detection Rationale</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#DADCE0] text-[11px]">
                      {(data.attack_matrix || []).map((row, idx) => (
                        <tr key={idx} className={row.status === 'ATTACK DETECTED' ? 'bg-[#FFEBEE]/30' : 'hover:bg-[#F5F6F8]'}>
                          <td className="py-2 px-3 font-semibold text-[#202124] font-sans">{row.vector_name}</td>
                          <td className="py-2 px-3">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                              row.status === 'ATTACK DETECTED'
                                ? 'bg-[#FFEBEE] text-[#C62828] border-[#FFCDD2]'
                                : 'bg-[#E8F5E9] text-[#2E7D32] border-[#C8E6C9]'
                            }`}>
                              {row.status}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-[#5F6368]">{row.risk_level}</td>
                          <td className="py-2 px-3 font-bold text-[#202124]">{row.score}</td>
                          <td className="py-2 px-3 text-[#5F6368] font-sans truncate max-w-xs">{row.detection_notes}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB: SECURITY LOGS */}
          {/* ========================================================================= */}
          {activeTab === 'logs' && data && (
            <div className="space-y-4">
              <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#DADCE0] pb-2.5">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                      Tamper-Evident Chained Audit Logs
                    </h3>
                    <p className="text-[11px] text-[#5F6368]">
                      Each event is cryptographically hashed and chained to previous entry for non-repudiation
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={handleCopyAllLogs}
                      className="px-2.5 py-1 text-xs rounded border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] font-medium flex items-center gap-1 cursor-pointer"
                    >
                      <Copy className="w-3 h-3 text-[#5F6368]" />
                      <span>{copiedLogHash === 'ALL_LOGS_COPIED' ? 'Copied' : 'Copy All'}</span>
                    </button>
                    <button
                      onClick={handleExportLogs}
                      className="px-2.5 py-1 text-xs rounded border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] font-medium flex items-center gap-1 cursor-pointer"
                    >
                      <Download className="w-3 h-3 text-[#5F6368]" />
                      <span>Export TXT</span>
                    </button>
                  </div>
                </div>

                {/* Filter and Search */}
                <div className="flex items-center gap-2 flex-wrap">
                  {(['ALL', 'ALERT', 'WARNING', 'VALID'] as const).map((f) => (
                    <button
                      key={f}
                      onClick={() => setLogFilter(f)}
                      className={`px-2.5 py-1 rounded text-xs font-medium border cursor-pointer ${
                        logFilter === f
                          ? 'bg-[#2457A6] text-white border-[#2457A6] font-bold'
                          : 'bg-white text-[#5F6368] border-[#DADCE0] hover:bg-[#F5F6F8]'
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                  <input
                    type="text"
                    value={logSearchQuery}
                    onChange={(e) => setLogSearchQuery(e.target.value)}
                    placeholder="Search logs..."
                    className="flex-1 bg-[#F5F6F8] border border-[#DADCE0] rounded px-3 py-1 text-xs font-mono text-[#202124]"
                  />
                </div>

                <div className="bg-[#F5F6F8] border border-[#DADCE0] rounded p-3 font-mono text-xs max-h-96 overflow-y-auto space-y-1.5">
                  {filteredLogs.map((log, i) => (
                    <div key={i} className="flex items-start justify-between gap-2 border-b border-[#DADCE0]/60 pb-1 last:border-b-0">
                      <div className="flex items-start gap-2">
                        <span className="text-[#5F6368] shrink-0">{log.time}</span>
                        <span className={`px-1 rounded text-[10px] font-bold shrink-0 ${
                          log.status === 'ALERT' || log.status === 'ACTION_REQUIRED'
                            ? 'bg-[#FFEBEE] text-[#C62828]'
                            : log.status === 'WARNING'
                            ? 'bg-[#FFF3E0] text-[#B26A00]'
                            : 'bg-[#E8F5E9] text-[#2E7D32]'
                        }`}>
                          {log.status}
                        </span>
                        <span className="text-[#202124]">{log.event}</span>
                      </div>
                      {log.event_hash && (
                        <span className="text-[10px] text-[#5F6368] font-mono shrink-0">
                          {log.event_hash.substring(0, 12)}...
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* TAB: LAB GUIDE */}
          {/* ========================================================================= */}
          {activeTab === 'guide' && (
            <div className="space-y-4">
              <div className="bg-white border border-[#DADCE0] rounded-md p-4 space-y-3">
                <h3 className="text-sm font-bold text-[#202124]">Local Research Lab Execution Guide</h3>
                <p className="text-xs text-[#5F6368]">
                  Step-by-step instructions for running this prototype in VS Code with Python and Flask.
                </p>

                <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0] space-y-2 text-xs">
                  <div className="font-bold text-[#202124]">1. Python Environment Setup</div>
                  <pre className="p-2.5 bg-white rounded border border-[#DADCE0] font-mono text-[11px] overflow-x-auto text-[#202124]">
{`# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# Install dependencies
pip install flask cryptography qiskit numpy`}
                  </pre>
                </div>

                <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0] space-y-2 text-xs">
                  <div className="font-bold text-[#202124]">2. Launch Flask Backend Server</div>
                  <pre className="p-2.5 bg-white rounded border border-[#DADCE0] font-mono text-[11px] overflow-x-auto text-[#202124]">
{`python3 app.py
# Backend running at http://127.0.0.1:5000`}
                  </pre>
                </div>

                <div className="p-3 bg-[#F5F6F8] rounded border border-[#DADCE0] space-y-2 text-xs">
                  <div className="font-bold text-[#202124]">3. Launch React Interface</div>
                  <pre className="p-2.5 bg-white rounded border border-[#DADCE0] font-mono text-[11px] overflow-x-auto text-[#202124]">
{`npm install
npm run dev
# Interface accessible at http://localhost:3000`}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* 5. Footer */}
      <footer className="bg-white border-t border-[#DADCE0] py-4 mt-8">
        <div className="max-w-[1200px] mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-[#5F6368]">
          <div>
            <span className="font-bold text-[#202124]">Quantum Digital Signature Security Analyzer</span>
            <span className="mx-1.5">&bull;</span>
            <span>Simulation-Based Cybersecurity Research Prototype</span>
          </div>
          <div className="font-mono text-[11px]">
            Python &bull; Flask &bull; Qiskit &bull; NumPy &bull; TypeScript &bull; React &bull; Chart.js
          </div>
        </div>
      </footer>

      {/* Modals */}
      {cbomOpen && data?.cbom && (
        <CbomModal
          cbom={data.cbom}
          isOpen={cbomOpen}
          onClose={() => setCbomOpen(false)}
        />
      )}

      {certModalOpen && data?.cryptographic_verification?.x509_certificate && (
        <CertificateModal
          cert={data.cryptographic_verification.x509_certificate}
          isOpen={certModalOpen}
          onClose={() => setCertModalOpen(false)}
        />
      )}
    </div>
  );
}
