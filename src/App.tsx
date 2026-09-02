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
  Moon,
  Sun,
  Layers,
  Cpu,
  Database,
  KeyRound,
  ExternalLink,
  ChevronRight,
  Filter,
  Search,
  Mail
} from 'lucide-react';
import { AnalysisResponse, SecurityLog } from './types';
import { SAMPLE_DATASETS, analyzeSecurityText, computeSha256 } from './analyzerEngine';
import { CbomModal } from './components/CbomModal';
import { CertificateModal } from './components/CertificateModal';
import { ExecutiveForensicAlert } from './components/ExecutiveForensicAlert';

export default function App() {
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [referenceHashInput, setReferenceHashInput] = useState<string>('');
  const [mode, setMode] = useState<string>('Automatic Detection');
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [copiedLogHash, setCopiedLogHash] = useState<string | null>(null);
  const [logFilter, setLogFilter] = useState<'ALL' | 'ALERT' | 'WARNING' | 'VALID'>('ALL');
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');
  const [currentTime, setCurrentTime] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'dashboard' | 'guide' | 'pqc'>('dashboard');
  const [isDark, setIsDark] = useState<boolean>(false);
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

  // Scroll logs to bottom
  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [data?.logs]);

  const handleLoadSample = async (sampleId: string) => {
    setLoading(true);
    try {
      const sample = SAMPLE_DATASETS[sampleId];
      if (!sample) return;

      const hash = await computeSha256(sample.content);
      const fileBytes = new TextEncoder().encode(sample.content).length;

      // Try server API first, fallback to client engine
      try {
        const formData = new FormData();
        formData.append('sample_id', sampleId);
        formData.append('attack_mode', mode);
        if (referenceHashInput) formData.append('reference_hash', referenceHashInput);

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

      const result = analyzeSecurityText(sample.content, sampleId, fileBytes, hash, mode, referenceHashInput);
      setData(result);
    } catch (err) {
      console.error('Failed to load sample:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    setSelectedFile(file);
    try {
      const fileBuffer = await file.arrayBuffer();
      const text = new TextDecoder('utf-8').decode(fileBuffer);
      const hash = await computeSha256(fileBuffer);

      try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('attack_mode', mode);
        if (referenceHashInput) formData.append('reference_hash', referenceHashInput);

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

      const result = analyzeSecurityText(text, file.name, file.size, hash, mode, referenceHashInput);
      setData(result);
    } catch (err) {
      console.error('Failed to analyze uploaded file:', err);
      alert('Error parsing uploaded file.');
    } finally {
      setLoading(false);
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
    const text = data.logs.map(l => `[${l.time}] [${l.status}] ${l.event} | Hash: ${l.event_hash || ''}`).join('\n');
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
    const text = data.logs.map(l => `[${l.time}] [${l.status}] ${l.event} | Hash: ${l.event_hash || ''}`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `qds_audit_trail_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredLogs = data?.logs.filter(log => {
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
  }) || [];

  const isAttack = data?.threat.status === 'ATTACK DETECTED';
  const riskColor = isDark
    ? data?.threat.risk_score && data.threat.risk_score >= 90
      ? 'text-rose-400 border-rose-500 bg-rose-500/10'
      : data?.threat.risk_score && data.threat.risk_score >= 60
      ? 'text-amber-400 border-amber-500 bg-amber-500/10'
      : 'text-emerald-400 border-emerald-500 bg-emerald-500/10'
    : data?.threat.risk_score && data.threat.risk_score >= 90
      ? 'text-rose-600 border-rose-500 bg-rose-50'
      : data?.threat.risk_score && data.threat.risk_score >= 60
      ? 'text-amber-600 border-amber-500 bg-amber-50'
      : 'text-emerald-600 border-emerald-500 bg-emerald-50';

  const riskBadge = isDark
    ? data?.threat.risk_score && data.threat.risk_score >= 90
      ? 'bg-rose-950/60 text-rose-300 border-rose-800'
      : data?.threat.risk_score && data.threat.risk_score >= 60
      ? 'bg-amber-950/60 text-amber-300 border-amber-800'
      : 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
    : data?.threat.risk_score && data.threat.risk_score >= 90
      ? 'bg-rose-100 text-rose-800 border-rose-300'
      : data?.threat.risk_score && data.threat.risk_score >= 60
      ? 'bg-amber-100 text-amber-800 border-amber-300'
      : 'bg-emerald-100 text-emerald-800 border-emerald-300';

  const cardRiskBorder = isDark
    ? isAttack
      ? 'border-rose-500/40 bg-[#111827] shadow-[0_0_20px_rgba(244,63,94,0.15)] ring-1 ring-rose-500/20'
      : 'border-emerald-500/40 bg-[#111827] shadow-[0_0_20px_rgba(16,185,129,0.15)] ring-1 ring-emerald-500/20'
    : isAttack
      ? 'border-rose-300 bg-white shadow-sm ring-1 ring-rose-100'
      : 'border-emerald-300 bg-white shadow-sm ring-1 ring-emerald-100';

  return (
    <div className={`min-h-screen font-sans flex flex-col justify-between transition-colors duration-200 ${
      isDark
        ? 'bg-[#090d16] text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200'
        : 'bg-slate-50 text-slate-900 selection:bg-slate-900 selection:text-white'
    }`}>
      <div>
        {/* Top Header */}
        <header className={`border-b backdrop-blur-md sticky top-0 z-50 transition-colors duration-200 ${
          isDark ? 'border-slate-800 bg-[#0d1322]/90' : 'border-slate-200 bg-white/90'
        }`}>
          <div className="w-full max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-white shadow-sm ${
                isDark
                  ? 'bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 shadow-cyan-500/20 ring-1 ring-cyan-400/30'
                  : 'bg-slate-900'
              }`}>
                <Atom className="w-5 h-5 text-sky-400 animate-spin-slow" />
              </div>
              <div>
                <div className="flex items-center gap-2.5">
                  <h1 className={`text-lg sm:text-xl font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Quantum Digital Signature Security Analyzer
                  </h1>
                  <span className={`hidden sm:inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold font-mono border ${
                    isDark ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30' : 'bg-slate-100 text-slate-700 border-slate-200'
                  }`}>
                    v2.6 PQC &amp; PKI
                  </span>
                </div>
                <p className={`text-xs sm:text-sm font-medium ${isDark ? 'text-cyan-400/90' : 'text-slate-500'}`}>
                  Quantum-Inspired Cyber Threat Detection for Digital Signature Security
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2.5 sm:gap-3 flex-wrap">
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-semibold ${
                isDark ? 'bg-slate-900 border-slate-700 text-slate-300' : 'bg-emerald-50 border-emerald-200 text-emerald-700'
              }`}>
                <span className={`w-2 h-2 rounded-full animate-pulse ${isDark ? 'bg-cyan-400 shadow-[0_0_8px_#22d3ee]' : 'bg-emerald-500'}`}></span>
                <span>QDS CHANNEL ACTIVE</span>
              </div>
              <div className={`hidden lg:block text-xs font-mono px-3 py-1.5 rounded-lg border ${
                isDark ? 'bg-slate-900/80 border-slate-800 text-slate-400' : 'bg-slate-100 border-slate-200 text-slate-600'
              }`}>
                {currentTime}
              </div>

              {/* Working Email Alert Button in Top Header */}
              <button
                onClick={() => setEmailAlertModalOpen(true)}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition flex items-center gap-1.5 shadow-sm cursor-pointer ${
                  isAttack || (data?.threat?.risk_score ?? 0) >= 60
                    ? 'bg-rose-600 hover:bg-rose-500 text-white border-rose-500 shadow-rose-900/40 animate-pulse'
                    : isDark
                      ? 'bg-rose-950/60 hover:bg-rose-900/70 text-rose-200 border-rose-700/50'
                      : 'bg-rose-50 hover:bg-rose-100 text-rose-800 border-rose-200'
                }`}
                title="Open Executive Forensic Email Alert Center (Recipient: deepakmurugaiyan@gmail.com)"
              >
                <Mail className={`w-3.5 h-3.5 ${isAttack || (data?.threat?.risk_score ?? 0) >= 60 ? 'text-white' : 'text-rose-500'}`} />
                <span>Email Alert</span>
                <span className={`w-2 h-2 rounded-full ${
                  isAttack || (data?.threat?.risk_score ?? 0) >= 60 ? 'bg-white animate-ping' : 'bg-rose-500'
                }`}></span>
              </button>

              {/* Theme Toggle Button */}
              <button
                onClick={() => setIsDark(!isDark)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition flex items-center gap-1.5 shadow-sm ${
                  isDark
                    ? 'bg-slate-800 hover:bg-slate-700 text-amber-300 border-slate-700'
                    : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
                }`}
                title={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
                aria-label="Toggle theme"
              >
                {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-slate-700" />}
                <span>{isDark ? 'Light Theme' : 'Dark Theme'}</span>
              </button>

              {/* CBOM Button */}
              <button
                onClick={() => setCbomOpen(true)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition flex items-center gap-1.5 shadow-sm ${
                  isDark
                    ? 'bg-cyan-950/40 hover:bg-cyan-900/50 text-cyan-300 border-cyan-500/40'
                    : 'bg-slate-100 hover:bg-slate-200 text-slate-800 border-slate-300'
                }`}
              >
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                <span>CBOM Inspector</span>
              </button>

              <button
                onClick={() => setActiveTab(activeTab === 'dashboard' ? 'guide' : 'dashboard')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition flex items-center gap-1.5 shadow-sm ${
                  isDark
                    ? 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                    : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
                }`}
              >
                <Server className={`w-3.5 h-3.5 ${isDark ? 'text-cyan-400' : 'text-slate-600'}`} />
                {activeTab === 'dashboard' ? 'Local VS Code Guide' : 'Dashboard'}
              </button>
            </div>
          </div>
        </header>

        {/* 1-Click Test Scenarios Bar */}
        <div className={`border-b py-2.5 px-4 sm:px-6 lg:px-8 transition-colors duration-200 ${
          isDark ? 'border-slate-800/80 bg-[#0b101c]/90' : 'border-slate-200 bg-white shadow-xs'
        }`}>
          <div className="w-full max-w-[1720px] mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
            <div className={`flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider flex-shrink-0 ${
              isDark ? 'text-slate-400' : 'text-slate-600'
            }`}>
              <Zap className={`w-4 h-4 ${isDark ? 'text-cyan-400' : 'text-amber-500'}`} />
              <span>1-Click Test Scenarios:</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(SAMPLE_DATASETS).map(([id, sample], idx) => {
                const isCurrent = data?.file.filename === id;
                const isCritical = sample.tag.includes('CRITICAL');
                const isHigh = sample.tag.includes('HIGH');
                const isPqc = sample.tag.includes('PQC');
                const isCryptoPass = sample.tag.includes('PASS');
                const isCryptoFail = sample.tag.includes('FAIL');

                return (
                  <button
                    key={id}
                    onClick={() => handleLoadSample(id)}
                    className={`text-xs px-2.5 py-1 rounded-md font-medium transition flex items-center gap-1.5 border ${
                      isCurrent
                        ? isDark
                          ? 'bg-cyan-500/20 border-cyan-400 text-cyan-200 shadow-sm shadow-cyan-500/30'
                          : 'bg-slate-900 text-white border-slate-900 shadow-xs'
                        : isDark
                        ? 'bg-slate-900/80 hover:bg-slate-800 border-slate-800 text-slate-300'
                        : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700 shadow-xs'
                    }`}
                  >
                    <span
                      className={`text-[10px] font-mono px-1 py-0.2 rounded font-bold ${
                        isCurrent
                          ? isDark
                            ? 'bg-cyan-500/30 text-cyan-100'
                            : 'bg-slate-800 text-slate-200'
                          : isPqc
                          ? isDark
                            ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                            : 'bg-purple-50 text-purple-700 border border-purple-200'
                          : isCryptoPass
                          ? isDark
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          : isCryptoFail || isCritical
                          ? isDark
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-rose-50 text-rose-700 border border-rose-200'
                          : isHigh
                          ? isDark
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            : 'bg-amber-50 text-amber-700 border border-amber-200'
                          : isDark
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      }`}
                    >
                      TEST {idx + 1}
                    </span>
                    <span>{sample.name.replace(/^Test \d+:\s*/, '')}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {activeTab === 'guide' ? (
          /* VS Code Local Execution Guide View */
          <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8">
            <div className={`border rounded-xl p-6 sm:p-8 shadow-sm space-y-6 ${
              isDark ? 'bg-[#111827] border-slate-800' : 'bg-white border-slate-200'
            }`}>
              <div className={`flex items-center gap-3 border-b pb-4 ${isDark ? 'border-slate-800' : 'border-slate-100'}`}>
                <div className={`w-10 h-10 rounded-lg border flex items-center justify-center ${
                  isDark ? 'bg-slate-900 border-slate-700 text-cyan-400' : 'bg-slate-100 border-slate-200 text-slate-800'
                }`}>
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h2 className={`text-xl font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>Local Python & VS Code Execution Instructions</h2>
                  <p className={`text-sm ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Run the exact Python Flask prototype locally in your VS Code environment</p>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className={`text-xs font-bold uppercase tracking-wider ${isDark ? 'text-cyan-400' : 'text-slate-700'}`}>Step 1: Open VS Code in the project folder</h3>
                <p className={`text-sm ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>The workspace contains all the native Flask backend and frontend files:</p>
                <div className="bg-slate-950 p-4 rounded-xl font-mono text-xs text-slate-200 border border-slate-800 space-y-1">
                  <div>📁 project-root/</div>
                  <div className="pl-4 text-emerald-400">├── app.py &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Flask API server &amp; endpoints (/api/upload, /)</div>
                  <div className="pl-4 text-sky-400">├── file_analyzer.py &nbsp;&nbsp;&nbsp;&nbsp;# SHA-256 computation, MIME magic &amp; forensic text ingestion</div>
                  <div className="pl-4 text-indigo-400">├── crypto_verifier.py &nbsp;&nbsp;# Mathematical RSA/ECDSA/CMS signature verification</div>
                  <div className="pl-4 text-teal-400">├── certificate_analyzer.py # X.509 PKI trust chain &amp; OCSP/CRL revocation</div>
                  <div className="pl-4 text-amber-400">├── replay_store.py &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# SQLite-backed stateful replay &amp; timestamp freshness cache</div>
                  <div className="pl-4 text-purple-400">├── pqc_analyzer.py &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# NIST FIPS 204 ML-DSA &amp; CycloneDX CBOM engine</div>
                  <div className="pl-4 text-rose-400">├── audit_logger.py &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Tamper-evident chained SHA-256 audit trail</div>
                  <div className="pl-4 text-sky-400">├── threat_detector.py &nbsp;&nbsp;# Multi-vector evidence-weighted risk scoring engine</div>
                  <div className="pl-4 text-blue-400">├── qds_engine.py &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Quantum Digital Signature &amp; QBER simulation</div>
                  <div className="pl-4 text-slate-400">├── templates/index.html &nbsp;# Full cybersecurity dashboard template</div>
                  <div className="pl-4 text-slate-400">├── static/style.css &nbsp;&nbsp;&nbsp;&nbsp;# High-contrast styling</div>
                  <div className="pl-4 text-slate-400">├── static/script.js &nbsp;&nbsp;&nbsp;&nbsp;# Chart.js integration &amp; dynamic UI handlers</div>
                  <div className="pl-4 text-rose-400">├── uploads/ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Upload folder with ready-to-test files</div>
                  <div className="pl-4 text-slate-500">└── requirements.txt &nbsp;&nbsp;&nbsp;&nbsp;# Flask, Werkzeug, pypdf, cryptography dependencies</div>
                </div>

                <h3 className={`text-xs font-bold uppercase tracking-wider pt-2 ${isDark ? 'text-cyan-400' : 'text-slate-700'}`}>Step 2: Start the Python Flask Server</h3>
                <p className={`text-sm ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>Execute in VS Code Terminal or PowerShell:</p>
                <div className="bg-slate-950 p-3 rounded-lg font-mono text-xs text-emerald-300 border border-slate-800 flex items-center justify-between">
                  <span>python app.py</span>
                  <span className="text-slate-400 font-sans text-[11px]">or: .\.venv\Scripts\python.exe app.py</span>
                </div>

                <h3 className={`text-xs font-bold uppercase tracking-wider pt-2 ${isDark ? 'text-cyan-400' : 'text-slate-700'}`}>Step 3: Access Live Local Prototype</h3>
                <p className={`text-sm ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>Open your browser at:</p>
                <div className={`p-3 rounded-lg font-mono text-xs border ${
                  isDark ? 'bg-slate-950 text-cyan-300 border-slate-800' : 'bg-slate-100 text-slate-900 border-slate-200'
                }`}>
                  http://127.0.0.1:5000
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => setActiveTab('dashboard')}
                  className={`px-4 py-2 rounded-lg font-semibold transition text-xs shadow-sm ${
                    isDark
                      ? 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-cyan-600/30'
                      : 'bg-slate-900 hover:bg-slate-800 text-white'
                  }`}
                >
                  Return to Live Dashboard
                </button>
              </div>
            </div>
          </div>
        ) : (
          /* Main Workspace Layout */
          <main className="w-full max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 py-5 sm:py-6 space-y-6">
            {/* Top 2-Column Balanced Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 lg:gap-6 items-start">
              {/* Left Column (6 Cols): Ingestion, PKI, Cache, Quantum Metrics */}
              <div className="lg:col-span-6 space-y-6">
                {/* 1. File Upload & Ingestion Card */}
                <div className={`border rounded-xl p-5 relative overflow-hidden transition-colors duration-200 ${
                  isDark ? 'bg-[#111827] border-slate-800 shadow-lg' : 'bg-white border-slate-200 shadow-xs'
                }`}>
                  <div className={`flex items-center justify-between pb-3.5 border-b mb-4 ${
                    isDark ? 'border-slate-800' : 'border-slate-100'
                  }`}>
                    <div className={`flex items-center gap-2 text-sm font-bold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                      <Upload className={`w-4 h-4 ${isDark ? 'text-cyan-400' : 'text-slate-700'}`} />
                      <span>1. Security File Ingestion</span>
                    </div>
                    <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                      isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}>
                      .TXT / .JSON / .CSV / .PDF / .P7S / .CRT
                    </span>
                  </div>

                  {/* Drag and Drop Zone */}
                  <div
                    onClick={() => fileInputRef.current?.click()}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                        handleFileUpload(e.dataTransfer.files[0]);
                      }
                    }}
                    className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition group ${
                      isDark
                        ? 'border-slate-700 hover:border-cyan-500/80 bg-slate-900/60 hover:bg-cyan-950/10'
                        : 'border-slate-200 hover:border-slate-400 bg-slate-50/50 hover:bg-slate-50'
                    }`}
                  >
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={(e) => {
                        if (e.target.files && e.target.files.length > 0) {
                          handleFileUpload(e.target.files[0]);
                        }
                      }}
                      accept=".txt,.json,.csv,.pdf,.p7s,.p7m,.crt,.cer,.pem,.der,.log"
                      className="hidden"
                    />
                    <div className={`w-10 h-10 rounded-full border flex items-center justify-center mx-auto mb-2.5 transition ${
                      isDark
                        ? 'bg-slate-800/80 border-slate-700 group-hover:border-cyan-500/50 text-cyan-400'
                        : 'bg-white border-slate-200 group-hover:border-slate-400 text-slate-700 shadow-xs'
                    }`}>
                      <FileText className="w-5 h-5" />
                    </div>
                    <p className={`text-xs font-semibold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                      Drag & drop security / signature file here
                    </p>
                    <p className={`text-[11px] mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                      or <span className={`underline font-medium ${isDark ? 'text-cyan-400' : 'text-slate-900'}`}>browse local disk</span>
                    </p>

                    {selectedFile && (
                      <div className={`mt-3 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-mono ${
                        isDark ? 'bg-cyan-950/60 border-cyan-500/40 text-cyan-300' : 'bg-slate-100 border-slate-200 text-slate-800'
                      }`}>
                        <FileCode className="w-3.5 h-3.5" />
                        <span>{selectedFile.name}</span>
                      </div>
                    )}
                  </div>

                  {/* Reference Hash Input */}
                  <div className="mt-3">
                    <label className={`text-[11px] font-semibold block mb-1 ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Optional Reference SHA-256 Digest (Integrity Verification):
                    </label>
                    <input
                      type="text"
                      value={referenceHashInput}
                      onChange={(e) => setReferenceHashInput(e.target.value)}
                      placeholder="e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                      className={`w-full font-mono text-[11px] px-3 py-1.5 rounded-lg border focus:outline-none ${
                        isDark ? 'bg-slate-900 border-slate-700 text-slate-200 focus:border-cyan-400' : 'bg-slate-50 border-slate-200 text-slate-800 focus:border-slate-900'
                      }`}
                    />
                  </div>

                  {/* Analysis Mode Selector */}
                  <div className="mt-3 space-y-1.5">
                    <label className={`text-xs font-bold uppercase tracking-wide ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                      Threat Detection Engine Mode:
                    </label>
                    <select
                      value={mode}
                      onChange={(e) => setMode(e.target.value)}
                      className={`w-full border rounded-lg px-3 py-2 text-xs font-medium focus:outline-none ${
                        isDark
                          ? 'bg-[#0d1322] border-slate-700 text-slate-200 focus:border-cyan-400'
                          : 'bg-slate-50 border-slate-200 text-slate-800 focus:ring-1 focus:ring-slate-900 focus:border-slate-900'
                      }`}
                    >
                      <option value="Automatic Detection">⚡ Automatic Threat Detection (Default - Recommended)</option>
                      <option value="Simulate: Replay Attack">Optional Simulation: Replay Attack</option>
                      <option value="Simulate: Forgery">Optional Simulation: Signature Forgery</option>
                      <option value="Simulate: Impersonation">Optional Simulation: Impersonation</option>
                      <option value="Simulate: Classical Channel Tampering">Optional Simulation: Channel Tampering</option>
                      <option value="Simulate: Intercept-Resend">Optional Simulation: Intercept-Resend</option>
                      <option value="Simulate: Entangle-and-Measure">Optional Simulation: Quantum Eavesdropping</option>
                    </select>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-2.5 mt-4">
                    <button
                      onClick={() => {
                        if (selectedFile) handleFileUpload(selectedFile);
                        else handleLoadSample('test_1_secure.txt');
                      }}
                      disabled={loading}
                      className={`flex-1 py-2 px-4 rounded-lg font-semibold text-xs shadow-xs transition flex items-center justify-center gap-2 ${
                        isDark
                          ? 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-cyan-500/20'
                          : 'bg-slate-900 hover:bg-slate-800 text-white'
                      }`}
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                      {loading ? 'Analyzing...' : 'Analyze File'}
                    </button>
                    <button
                      onClick={() => {
                        setSelectedFile(null);
                        setReferenceHashInput('');
                        setMode('Automatic Detection');
                        handleLoadSample('test_1_secure.txt');
                      }}
                      className={`px-3.5 py-2 rounded-lg font-semibold text-xs border shadow-xs transition ${
                        isDark
                          ? 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
                          : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
                      }`}
                    >
                      Reset
                    </button>
                  </div>
                </div>

                {/* 2. Cryptographic Verification Layer & PKI Card */}
                <div className={`border rounded-xl p-5 transition-colors duration-200 ${
                  isDark ? 'bg-[#111827] border-slate-800 shadow-lg' : 'bg-white border-slate-200 shadow-xs'
                }`}>
                  <div className={`flex items-center justify-between pb-3.5 border-b mb-4 ${
                    isDark ? 'border-slate-800' : 'border-slate-100'
                  }`}>
                    <div className={`flex items-center gap-2 text-sm font-bold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                      <KeyRound className={`w-4 h-4 ${isDark ? 'text-cyan-400' : 'text-slate-700'}`} />
                      <span>2. Mathematical Signature & PKI</span>
                    </div>
                    <span className={`text-[11px] font-mono px-2 py-0.5 rounded font-bold border ${
                      data?.cryptographic_verification?.is_verified
                        ? isDark ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}>
                      {data?.cryptographic_verification?.verification_badge || 'LAYER 2'}
                    </span>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div className={`p-3 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'
                    }`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-[10px] uppercase font-bold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Mathematical Verification</span>
                        <span className={`font-mono font-bold ${
                          data?.cryptographic_verification?.mathematical_verification === 'VALID'
                            ? 'text-emerald-400'
                            : data?.cryptographic_verification?.mathematical_verification === 'FAILED'
                            ? 'text-rose-400'
                            : isDark ? 'text-slate-300' : 'text-slate-700'
                        }`}>
                          {data?.cryptographic_verification?.mathematical_verification || 'UNAVAILABLE'}
                        </span>
                      </div>
                      <p className={`text-[11px] leading-relaxed ${isDark ? 'text-slate-300' : 'text-slate-600'}`}>
                        {data?.cryptographic_verification?.details}
                      </p>
                    </div>

                    {/* Certificate Quick Info */}
                    <div className={`p-3 rounded-lg border flex items-center justify-between ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'
                    }`}>
                      <div>
                        <span className={`text-[10px] uppercase font-bold block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>X.509 Certificate</span>
                        <span className={`font-semibold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                          {data?.certificate_analysis?.certificate_present ? `${data.certificate_analysis.status} (${data.certificate_analysis.public_key_algorithm})` : 'Not Present'}
                        </span>
                      </div>
                      {data?.certificate_analysis?.certificate_present && (
                        <button
                          onClick={() => setCertModalOpen(true)}
                          className={`text-[11px] px-2.5 py-1 rounded font-semibold border flex items-center gap-1 transition ${
                            isDark ? 'bg-cyan-950/50 hover:bg-cyan-900/60 text-cyan-300 border-cyan-500/40' : 'bg-white hover:bg-slate-50 text-slate-800 border-slate-300'
                          }`}
                        >
                          <span>View PKI</span>
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* 3. SHA-256 Digest & Stateful Replay Cache */}
                <div className={`border rounded-xl p-5 transition-colors duration-200 ${
                  isDark ? 'bg-[#111827] border-slate-800 shadow-lg' : 'bg-white border-slate-200 shadow-xs'
                }`}>
                  <div className={`flex items-center justify-between pb-3.5 border-b mb-4 ${
                    isDark ? 'border-slate-800' : 'border-slate-100'
                  }`}>
                    <div className={`flex items-center gap-2 text-sm font-bold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                      <Database className={`w-4 h-4 ${isDark ? 'text-cyan-400' : 'text-slate-700'}`} />
                      <span>3. SHA-256 &amp; Stateful Replay Cache</span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                      data?.stateful_replay?.is_stateful_replay
                        ? isDark ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-rose-50 text-rose-700 border-rose-200'
                        : isDark ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    }`}>
                      {data?.stateful_replay?.stateful_replay_type || 'FRESH'}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className={`col-span-2 p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-[10px] uppercase font-bold ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>SHA-256 Hash Digest</span>
                        <button
                          onClick={handleCopyHash}
                          className={`text-[10px] flex items-center gap-1 font-medium ${
                            isDark ? 'text-cyan-400 hover:text-cyan-300' : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          {copiedHash ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <div className={`font-mono text-[11px] break-all p-2 rounded border select-all ${
                        isDark ? 'bg-slate-950 text-slate-300 border-slate-800' : 'bg-white text-slate-800 border-slate-200'
                      }`}>
                        {data?.file.sha256 || 'Loading hash...'}
                      </div>
                    </div>

                    <div className={`p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] uppercase font-bold block mb-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Cache Hit Count</span>
                      <span className={`font-mono font-bold ${data?.stateful_replay && data.stateful_replay.hit_count > 1 ? 'text-rose-400' : isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                        {data?.stateful_replay?.hit_count || 1} observation(s)
                      </span>
                    </div>

                    <div className={`p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] uppercase font-bold block mb-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Timestamp Freshness</span>
                      <span className={`font-mono font-bold ${
                        data?.stateful_replay?.timestamp_freshness === 'FRESH'
                          ? 'text-emerald-400'
                          : data?.stateful_replay?.timestamp_freshness === 'STALE'
                          ? 'text-amber-400'
                          : isDark ? 'text-slate-400' : 'text-slate-600'
                      }`}>
                        {data?.stateful_replay?.timestamp_freshness || 'UNKNOWN'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* 4. Quantum Security Metrics Panel */}
                <div className={`border rounded-xl p-5 transition-colors duration-200 ${
                  isDark ? 'bg-[#111827] border-slate-800 shadow-lg' : 'bg-white border-slate-200 shadow-xs'
                }`}>
                  <div className={`flex items-center justify-between pb-3.5 border-b mb-4 ${
                    isDark ? 'border-slate-800' : 'border-slate-100'
                  }`}>
                    <div className={`flex items-center gap-2 text-sm font-bold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                      <Atom className={`w-4 h-4 ${isDark ? 'text-cyan-400' : 'text-slate-700'}`} />
                      <span>4. Quantum Security Metrics (QDS)</span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                      isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}>
                      SIMULATED STATE
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                    <div className={`p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] uppercase font-bold block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>QBER Error</span>
                      <span className={`text-sm font-mono font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>{data?.quantum.qber_percentage}</span>
                      <span className={`text-[9px] block ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>&le; 11% Limit</span>
                    </div>

                    <div className={`p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] uppercase font-bold block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Mismatch Rate</span>
                      <span className={`text-sm font-mono font-bold ${isDark ? 'text-amber-400' : 'text-amber-700'}`}>{data?.quantum.mismatch_rate_percentage}</span>
                      <span className={`text-[9px] block ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>{data?.quantum.mismatches}/{data?.quantum.number_of_rounds}</span>
                    </div>

                    <div className={`p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] uppercase font-bold block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Matching Rate</span>
                      <span className={`text-sm font-mono font-bold ${isDark ? 'text-emerald-400' : 'text-emerald-700'}`}>{data?.quantum.matching_rate_percentage}</span>
                      <span className={`text-[9px] block ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>{data?.quantum.matches}/{data?.quantum.number_of_rounds}</span>
                    </div>

                    <div className={`p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] uppercase font-bold block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Quantum Risk</span>
                      <span className={`text-xs font-bold ${
                        data?.quantum.quantum_risk === 'CRITICAL'
                          ? isDark ? 'text-rose-400' : 'text-rose-700'
                          : isDark ? 'text-emerald-400' : 'text-emerald-700'
                      }`}>
                        {data?.quantum.quantum_risk}
                      </span>
                    </div>

                    <div className={`p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] uppercase font-bold block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Eavesdrop Prob</span>
                      <span className={`text-sm font-mono font-bold ${isDark ? 'text-rose-400' : 'text-rose-700'}`}>{data?.quantum.estimated_eavesdropping_probability}</span>
                    </div>

                    <div className={`p-2.5 rounded-lg border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] uppercase font-bold block ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Security Level</span>
                      <span className={`text-xs font-bold ${
                        data?.quantum.quantum_risk === 'CRITICAL'
                          ? isDark ? 'text-rose-400' : 'text-rose-700'
                          : isDark ? 'text-emerald-400' : 'text-emerald-700'
                      }`}>
                        {data?.quantum.security_level}
                      </span>
                    </div>
                  </div>

                  <p className={`mt-2.5 text-[10.5px] text-center italic ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>
                    ⚡ Quantum threat detection is simulated for digital signature channel monitoring.
                  </p>
                </div>
              </div>

              {/* Right Column (6 Cols): Main Threat Analysis, PQC Readiness & Forensic Summary */}
              <div className="lg:col-span-6 space-y-6">
                {/* 6. MAIN THREAT DETECTION RESULT CARD */}
                <div className={`border rounded-xl p-6 transition-colors duration-200 ${cardRiskBorder}`}>
                  {/* Header Banner */}
                  <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b ${
                    isDark ? 'border-slate-800' : 'border-slate-100'
                  }`}>
                    <div>
                      <div className="flex items-center gap-2 mb-1.5">
                        <span
                          className={`text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${
                            isAttack
                              ? isDark ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-rose-50 text-rose-700 border-rose-200'
                              : isDark ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          }`}
                        >
                          {isAttack ? '🚨 THREAT DETECTED' : '🛡️ SYSTEM SECURE'}
                        </span>
                        <span className={`text-xs font-mono ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                          Case: {data?.case_id || data?.summary?.case_id || 'AUDIT-001'}
                        </span>
                      </div>
                      <h2 className={`text-2xl font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                        {data?.threat.detected_threat}
                      </h2>
                      <p className={`text-xs sm:text-sm font-medium mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                        Category: {data?.threat.threat_category}
                      </p>
                    </div>

                    {/* Risk Gauge */}
                    <div className={`flex sm:flex-col items-center justify-between sm:justify-center p-3 rounded-xl border min-w-[120px] ${
                      isDark ? 'bg-slate-900/90 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <div className={`w-14 h-14 rounded-full border-4 flex flex-col items-center justify-center font-mono ${riskColor}`}>
                        <span className="text-lg font-bold leading-none">{data?.threat.risk_score}</span>
                        <span className={`text-[9px] font-normal ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>/ 100</span>
                      </div>
                      <div className={`mt-2 text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${riskBadge}`}>
                        {data?.threat.risk} RISK
                      </div>
                    </div>
                  </div>

                  {/* Threat Details Body */}
                  <div className="mt-5 space-y-4">
                    {/* Reason */}
                    <div className={`p-3.5 rounded-xl border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] font-bold uppercase tracking-wider block mb-1 ${
                        isDark ? 'text-slate-400' : 'text-slate-500'
                      }`}>
                        WHY WAS IT DETECTED?
                      </span>
                      <p className={`text-xs sm:text-sm leading-relaxed ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>{data?.threat.reason}</p>
                    </div>

                    {/* Evidence */}
                    <div className={`p-3.5 rounded-xl border ${
                      isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'
                    }`}>
                      <span className={`text-[10px] font-bold uppercase tracking-wider block mb-1.5 ${
                        isDark ? 'text-slate-400' : 'text-slate-500'
                      }`}>
                        EVIDENCE DETECTED
                      </span>
                      <ul className="space-y-1.5">
                        {data?.threat.evidence && data.threat.evidence.length > 0 ? (
                          data.threat.evidence.map((ev, i) => (
                            <li key={i} className={`text-xs font-mono px-2.5 py-1.5 rounded border flex items-center gap-1.5 shadow-2xs ${
                              isDark ? 'bg-slate-950 text-slate-200 border-slate-800' : 'bg-white text-slate-800 border-slate-200'
                            }`}>
                              <CheckCircle className={`w-3.5 h-3.5 flex-shrink-0 ${isDark ? 'text-cyan-400' : 'text-slate-600'}`} />
                              <span>{ev}</span>
                            </li>
                          ))
                        ) : (
                          <li className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>✓ No suspicious indicators found.</li>
                        )}
                      </ul>
                    </div>

                    {/* FIRST ACTION TO OVERCOME */}
                    <div className={`border rounded-xl p-4 flex items-start gap-3 ${
                      isDark ? 'bg-rose-950/30 border-rose-500/30' : 'bg-rose-50/80 border-rose-200'
                    }`}>
                      <div className={`w-8 h-8 rounded-lg border flex items-center justify-center flex-shrink-0 ${
                        isDark ? 'bg-rose-900/50 border-rose-700 text-rose-300' : 'bg-rose-100 border-rose-200 text-rose-700'
                      }`}>
                        <ShieldAlert className="w-4 h-4" />
                      </div>
                      <div>
                        <h4 className={`text-xs font-bold uppercase tracking-wider mb-1 ${
                          isDark ? 'text-rose-300' : 'text-rose-900'
                        }`}>
                          🛡️ FIRST ACTION TO OVERCOME
                        </h4>
                        <p className={`text-xs sm:text-sm font-semibold ${isDark ? 'text-rose-200' : 'text-rose-800'}`}>
                          {data?.threat.first_action}
                        </p>
                      </div>
                    </div>

                    {/* HOW TO PREVENT / OVERCOME */}
                    <div className={`border rounded-xl p-4 flex items-start gap-3 ${
                      isDark ? 'bg-sky-950/30 border-cyan-500/30' : 'bg-sky-50/80 border-sky-200'
                    }`}>
                      <div className={`w-8 h-8 rounded-lg border flex items-center justify-center flex-shrink-0 ${
                        isDark ? 'bg-sky-900/50 border-cyan-700 text-cyan-300' : 'bg-sky-100 border-sky-200 text-sky-700'
                      }`}>
                        <Lock className="w-4 h-4" />
                      </div>
                      <div>
                        <h4 className={`text-xs font-bold uppercase tracking-wider mb-1 ${
                          isDark ? 'text-cyan-300' : 'text-sky-900'
                        }`}>
                          🔐 HOW TO PREVENT / OVERCOME
                        </h4>
                        <p className={`text-xs sm:text-sm leading-relaxed ${isDark ? 'text-slate-200' : 'text-sky-950'}`}>
                          {data?.threat.recommendation}
                        </p>
                      </div>
                    </div>

                    {/* Additional Vectors if Multiple */}
                    {data?.threat.additional_threats && data.threat.additional_threats.length > 0 && (
                      <div className={`p-3 border rounded-xl text-xs flex items-center gap-2 ${
                        isDark ? 'bg-amber-950/30 border-amber-500/30 text-amber-200' : 'bg-amber-50 border-amber-200 text-amber-900'
                      }`}>
                        <AlertTriangle className={`w-4 h-4 flex-shrink-0 ${isDark ? 'text-amber-400' : 'text-amber-600'}`} />
                        <div>
                          <span className="font-bold">Additional Threat Vectors Detected: </span>
                          <span className="font-mono">{data.threat.additional_threats.join(', ')}</span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* 7. Post-Quantum Cryptography Assessment Card */}
                <div className={`border rounded-xl p-5 transition-colors duration-200 ${
                  isDark ? 'bg-[#111827] border-slate-800 shadow-lg' : 'bg-white border-slate-200 shadow-xs'
                }`}>
                  <div className={`flex items-center justify-between pb-3.5 border-b mb-4 ${
                    isDark ? 'border-slate-800' : 'border-slate-100'
                  }`}>
                    <div className={`flex items-center gap-2 text-sm font-bold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                      <Cpu className={`w-4 h-4 ${isDark ? 'text-purple-400' : 'text-purple-700'}`} />
                      <span>Post-Quantum Cryptography (PQC) Readiness</span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                      data?.post_quantum_assessment?.is_quantum_safe
                        ? isDark ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : isDark ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-amber-50 text-amber-700 border-amber-200'
                    }`}>
                      {data?.post_quantum_assessment?.pqc_status || 'ASSESSMENT'}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                    <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'}`}>
                      <span className={`text-[10px] uppercase font-bold block mb-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Detected Algo</span>
                      <span className="font-mono font-bold text-cyan-400">{data?.post_quantum_assessment?.detected_algorithm}</span>
                    </div>
                    <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'}`}>
                      <span className={`text-[10px] uppercase font-bold block mb-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>NIST Standard</span>
                      <span className={`font-semibold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>{data?.post_quantum_assessment?.nist_standard}</span>
                    </div>
                    <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'}`}>
                      <span className={`text-[10px] uppercase font-bold block mb-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>PQC Readiness</span>
                      <span className="font-mono font-bold text-emerald-400">{data?.post_quantum_assessment?.pqc_readiness_score}/100</span>
                    </div>
                    <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-100'}`}>
                      <span className={`text-[10px] uppercase font-bold block mb-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Migration Target</span>
                      <span className="font-mono font-bold text-purple-400">{data?.post_quantum_assessment?.recommended_pqc}</span>
                    </div>
                  </div>

                  <div className={`mt-3 p-3 rounded-lg border text-xs leading-relaxed ${
                    isDark ? 'bg-slate-900/60 border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'
                  }`}>
                    <span className="font-bold">Crypto-Agility Analysis: </span>
                    {data?.post_quantum_assessment?.crypto_agility_rationale}
                  </div>
                </div>

                {/* 8. Executive Forensic Summary */}
                <div className={`border rounded-xl p-4 sm:p-5 flex flex-col justify-between transition-colors duration-200 ${
                  isDark ? 'bg-[#111827] border-slate-800 shadow-xl ring-1 ring-slate-800/60' : 'bg-white border-slate-200 shadow-sm ring-1 ring-slate-100'
                }`}>
                  <div>
                    <div className={`flex items-center justify-between pb-3 border-b mb-3 ${
                      isDark ? 'border-slate-800' : 'border-slate-100'
                    }`}>
                      <div className="flex items-center gap-2">
                        <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
                          isDark ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'bg-slate-100 text-slate-800 border border-slate-200'
                        }`}>
                          <FileText className="w-4 h-4" />
                        </div>
                        <div>
                          <h3 className={`text-sm font-bold tracking-tight ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                            Executive Forensic Summary
                          </h3>
                          <span className={`text-[10px] font-mono block ${isDark ? 'text-cyan-400/80' : 'text-slate-500'}`}>
                            NIST FIPS 204/205 Baseline
                          </span>
                        </div>
                      </div>
                      <div className="flex gap-1.5 sm:gap-2 shrink-0">
                        <button
                          onClick={() => window.print()}
                          className={`text-xs px-2.5 py-1.5 rounded-lg flex items-center gap-1 font-semibold shadow-2xs border transition ${
                            isDark
                              ? 'bg-slate-800/90 hover:bg-slate-700 text-slate-300 border-slate-700'
                              : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
                          }`}
                        >
                          <Printer className="w-3.5 h-3.5" />
                          <span className="hidden sm:inline">Print</span>
                        </button>
                        <button
                          onClick={handleExportJSON}
                          className={`text-xs px-2.5 sm:px-3 py-1.5 rounded-lg flex items-center gap-1 font-semibold shadow-2xs transition ${
                            isDark
                              ? 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-cyan-600/30'
                              : 'bg-slate-900 hover:bg-slate-800 text-white'
                          }`}
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>JSON</span>
                        </button>
                      </div>
                    </div>

                    <div className={`text-xs space-y-2 p-3 sm:p-3.5 rounded-xl border ${
                      isDark ? 'bg-slate-900/80 border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-100 text-slate-700'
                    }`}>
                      <div className="flex items-center justify-between pb-1.5 border-b border-slate-800/40">
                        <span className="font-semibold text-slate-400">Case Identifier:</span>
                        <span className="font-mono text-cyan-400 font-bold">{data?.case_id || data?.summary?.case_id}</span>
                      </div>
                      <div className="flex items-center justify-between pb-1.5 border-b border-slate-800/40">
                        <span className="font-semibold text-slate-400">Target File:</span>
                        <span className="font-mono font-medium truncate max-w-[280px]">{data?.file.filename} ({data?.file.file_size})</span>
                      </div>
                      <div className="flex items-center justify-between pb-1.5 border-b border-slate-800/40">
                        <span className="font-semibold text-slate-400">Overall Status:</span>
                        <span className="font-bold">{data?.summary.overall_status}</span>
                      </div>
                      <div className="flex items-center justify-between pb-1.5 border-b border-slate-800/40">
                        <span className="font-semibold text-slate-400">Risk Assessment:</span>
                        <span className={`font-mono font-bold ${
                          data?.summary.risk_score && data.summary.risk_score >= 60 ? 'text-rose-400' : 'text-emerald-400'
                        }`}>
                          {data?.summary.risk_level} ({data?.summary.risk_score}/100)
                        </span>
                      </div>
                      <div className="pt-0.5">
                        <span className="font-semibold text-slate-400 block mb-1">Executive Directive:</span>
                        <p className={`text-[11.5px] leading-relaxed font-medium ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                          {data?.summary.recommendation_summary}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className={`mt-3 pt-2 border-t text-[10px] text-center ${isDark ? 'border-slate-800/80 text-slate-500' : 'border-slate-100 text-slate-400'}`}>
                    Post-quantum cryptographic evaluation compliant with NIST FIPS 204/205.
                  </div>
                </div>
              </div>
            </div>

            {/* FULL-WIDTH SECTION: Executive Forensic Alert & Automatic Email Notification */}
            {data && (emailAlertModalOpen || isAttack || (data.threat?.risk_score ?? 0) >= 60 || data.threat?.risk === 'HIGH' || data.threat?.risk === 'CRITICAL' || data.forensic_summary?.risk_level === 'HIGH' || data.forensic_summary?.risk_level === 'CRITICAL') && (
              <ExecutiveForensicAlert
                data={data}
                isDark={isDark}
                isOpen={emailAlertModalOpen}
                onOpenChange={setEmailAlertModalOpen}
              />
            )}

            {/* FULL-WIDTH SECTION: Tamper-Evident Chained Logs */}
            <div className={`border rounded-xl p-5 sm:p-6 transition-colors duration-200 w-full ${
              isDark ? 'bg-[#111827] border-slate-800 shadow-xl ring-1 ring-slate-800/60' : 'bg-white border-slate-200 shadow-sm ring-1 ring-slate-100'
            }`}>
              {/* Header with Title, Filter Chips, Search and Actions */}
              <div className={`flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b mb-4 ${
                isDark ? 'border-slate-800' : 'border-slate-100'
              }`}>
                <div className="flex items-center gap-3">
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                    isDark ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'bg-slate-100 text-slate-800 border border-slate-200'
                  }`}>
                    <Terminal className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className={`text-base font-bold tracking-tight ${isDark ? 'text-slate-100' : 'text-slate-900'}`}>
                        Tamper-Evident Chained Logs
                      </h3>
                      <span className={`text-[11px] font-mono px-2 py-0.5 rounded font-semibold border ${
                        isDark ? 'bg-cyan-950/60 text-cyan-300 border-cyan-500/30' : 'bg-slate-100 text-slate-700 border-slate-200'
                      }`}>
                        {filteredLogs.length} Event{filteredLogs.length !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <span className={`text-xs font-mono block mt-0.5 ${isDark ? 'text-cyan-400/80' : 'text-slate-500'}`}>
                      SHA-256 Chained Cryptographic Trail &bull; Real-Time Immutability Verification
                    </span>
                  </div>
                </div>

                {/* Filter Chips, Search, & Action Controls */}
                <div className="flex flex-wrap items-center gap-2 sm:gap-2.5">
                  {/* Category Filter Chips */}
                  <div className={`inline-flex rounded-lg p-0.5 border ${isDark ? 'bg-slate-900 border-slate-800' : 'bg-slate-100 border-slate-200'}`}>
                    <button
                      onClick={() => setLogFilter('ALL')}
                      className={`text-xs px-2.5 py-1 rounded-md font-semibold transition ${
                        logFilter === 'ALL'
                          ? isDark ? 'bg-cyan-600 text-white shadow-xs' : 'bg-white text-slate-900 shadow-xs'
                          : isDark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      All ({data?.logs.length || 0})
                    </button>
                    <button
                      onClick={() => setLogFilter('ALERT')}
                      className={`text-xs px-2.5 py-1 rounded-md font-semibold transition flex items-center gap-1 ${
                        logFilter === 'ALERT'
                          ? 'bg-rose-600 text-white shadow-xs'
                          : isDark ? 'text-rose-400 hover:text-rose-300' : 'text-rose-700 hover:text-rose-800'
                      }`}
                    >
                      <span>Alerts</span>
                      <span className="text-[10px] font-mono">({data?.logs.filter(l => l.status === 'ALERT' || l.status === 'ACTION_REQUIRED').length || 0})</span>
                    </button>
                    <button
                      onClick={() => setLogFilter('WARNING')}
                      className={`text-xs px-2.5 py-1 rounded-md font-semibold transition flex items-center gap-1 ${
                        logFilter === 'WARNING'
                          ? 'bg-amber-600 text-white shadow-xs'
                          : isDark ? 'text-amber-400 hover:text-amber-300' : 'text-amber-700 hover:text-amber-800'
                      }`}
                    >
                      <span>Warnings</span>
                      <span className="text-[10px] font-mono">({data?.logs.filter(l => l.status === 'WARNING').length || 0})</span>
                    </button>
                    <button
                      onClick={() => setLogFilter('VALID')}
                      className={`text-xs px-2.5 py-1 rounded-md font-semibold transition flex items-center gap-1 ${
                        logFilter === 'VALID'
                          ? 'bg-emerald-600 text-white shadow-xs'
                          : isDark ? 'text-emerald-400 hover:text-emerald-300' : 'text-emerald-700 hover:text-emerald-800'
                      }`}
                    >
                      <span>Integrity OK</span>
                    </button>
                  </div>

                  {/* Search Filter Box */}
                  <div className="relative min-w-[160px] sm:min-w-[200px]">
                    <Search className={`w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 ${isDark ? 'text-slate-500' : 'text-slate-400'}`} />
                    <input
                      type="text"
                      value={logSearchQuery}
                      onChange={(e) => setLogSearchQuery(e.target.value)}
                      placeholder="Filter event logs..."
                      className={`w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border font-mono focus:outline-none transition ${
                        isDark
                          ? 'bg-slate-900 border-slate-700 text-slate-200 placeholder-slate-500 focus:border-cyan-400'
                          : 'bg-white border-slate-200 text-slate-800 placeholder-slate-400 focus:border-slate-800 shadow-2xs'
                      }`}
                    />
                  </div>

                  {/* Copy All Logs */}
                  <button
                    onClick={handleCopyAllLogs}
                    className={`text-xs px-2.5 py-1.5 rounded-lg font-semibold shadow-2xs border transition flex items-center gap-1.5 shrink-0 ${
                      isDark
                        ? 'bg-slate-800/90 hover:bg-slate-700 text-slate-200 border-slate-700 hover:border-cyan-500/40'
                        : 'bg-white hover:bg-slate-50 text-slate-800 border-slate-200 hover:border-slate-300'
                    }`}
                    title="Copy all logs to clipboard"
                  >
                    {copiedLogHash === 'ALL_LOGS_COPIED' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-cyan-500" />
                        <span className="hidden sm:inline">Copy All</span>
                      </>
                    )}
                  </button>

                  {/* Export Logs Button */}
                  <button
                    onClick={handleExportLogs}
                    className={`text-xs px-3 py-1.5 rounded-lg font-semibold shadow-2xs border transition flex items-center gap-1.5 shrink-0 ${
                      isDark
                        ? 'bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-500 shadow-cyan-600/30'
                        : 'bg-slate-900 hover:bg-slate-800 text-white border-slate-900'
                    }`}
                  >
                    <Download className="w-3.5 h-3.5 text-white" />
                    <span>Export Trail</span>
                  </button>
                </div>
              </div>

              {/* Terminal Logs Viewport - Spans Full Width */}
              <div className="bg-slate-950 text-slate-200 p-3.5 sm:p-4 rounded-xl font-mono text-xs space-y-2 min-h-[220px] max-h-[360px] overflow-y-auto border border-slate-800 shadow-inner scrollbar-thin scrollbar-thumb-slate-800 w-full">
                {filteredLogs.length > 0 ? (
                  filteredLogs.map((log, i) => {
                    const isAlert = log.status === 'ALERT' || log.status === 'ACTION_REQUIRED';
                    const isWarn = log.status === 'WARNING';
                    const isCopied = copiedLogHash === log.event_hash;

                    return (
                      <div
                        key={i}
                        className={`p-2.5 sm:p-3 rounded-lg border transition-colors ${
                          isAlert
                            ? 'bg-rose-950/25 border-rose-500/30 text-rose-200'
                            : isWarn
                            ? 'bg-amber-950/25 border-amber-500/30 text-amber-200'
                            : 'bg-slate-900/60 border-slate-800/80 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 text-[11px] mb-1.5">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-slate-400">[{log.time}]</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                              isAlert
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : isWarn
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            }`}>
                              {log.status}
                            </span>
                          </div>

                          {log.event_hash && (
                            <button
                              onClick={() => handleCopyLogHash(log.event_hash!)}
                              className="text-[10px] font-mono text-cyan-400/90 hover:text-cyan-300 flex items-center gap-1 transition px-2 py-0.5 rounded hover:bg-slate-800/60 border border-transparent hover:border-slate-700"
                              title="Copy this event SHA-256 hash"
                            >
                              {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              <span>{isCopied ? 'Hash Copied' : 'Copy Hash'}</span>
                            </button>
                          )}
                        </div>

                        <div className="text-xs leading-relaxed font-sans sm:font-mono font-medium text-slate-100">
                          {log.event}
                        </div>

                        {log.event_hash && (
                          <div className="mt-2 pt-1.5 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px] text-cyan-400/90 font-mono select-all">
                            <div className="flex items-center gap-1.5 overflow-hidden">
                              <span className="text-slate-500 text-[10px] uppercase font-sans shrink-0">Chain Hash:</span>
                              <span className="truncate">{log.event_hash}</span>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })
                ) : (
                  <div className="py-8 text-center text-slate-500">
                    <p className="text-xs font-mono">No logs match the selected filter criteria.</p>
                  </div>
                )}
                <div ref={logEndRef} />
              </div>

              {/* Terminal Footer Status Bar */}
              <div className={`mt-3.5 pt-3 border-t flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs ${
                isDark ? 'border-slate-800/80 text-slate-400' : 'border-slate-100 text-slate-500'
              }`}>
                <div className="flex items-center gap-3">
                  <span>Total Events in Chain: <strong className="font-mono text-cyan-400">{data?.logs.length || 0}</strong></span>
                  {logFilter !== 'ALL' && (
                    <span className="text-slate-400 font-mono text-[11px]">
                      (Filtered view: {filteredLogs.length})
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2 font-mono text-xs text-emerald-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#34d399]"></span>
                  <span className="font-semibold">INTEGRITY VERIFIED &bull; CHAIN INTACT</span>
                </div>
              </div>
            </div>

            {/* Bottom Full-Width Section: 8-Row Attack Scenario Analysis Matrix */}
            <div className={`border rounded-xl p-4 sm:p-5 transition-colors duration-200 w-full ${
              isDark ? 'bg-[#111827] border-slate-800 shadow-lg' : 'bg-white border-slate-200 shadow-xs'
            }`}>
              <div className={`flex items-center justify-between pb-3.5 border-b mb-3.5 ${
                isDark ? 'border-slate-800' : 'border-slate-100'
              }`}>
                <div className={`flex items-center gap-2 text-sm font-bold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                  <Activity className={`w-4 h-4 ${isDark ? 'text-cyan-400' : 'text-slate-700'}`} />
                  <span>Attack Scenario Analysis Matrix</span>
                </div>
                <span className={`text-xs font-medium px-2 py-0.5 rounded border ${
                  isDark ? 'bg-slate-800/80 text-slate-300 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200'
                }`}>
                  8 Vector Forensic Matrix
                </span>
              </div>

              <div className="overflow-x-auto w-full scrollbar-thin">
                <table className="w-full text-left text-xs border-collapse table-auto md:table-fixed">
                  <thead>
                    <tr className={`border-b text-[10px] uppercase font-bold tracking-wider ${
                      isDark ? 'border-slate-800 text-slate-400 bg-slate-900/90' : 'border-slate-200 text-slate-500 bg-slate-50'
                    }`}>
                      <th className="py-2.5 px-3 md:w-[20%]">Attack Vector</th>
                      <th className="py-2.5 px-3 md:w-[16%]">Status</th>
                      <th className="py-2.5 px-3 md:w-[14%]">Risk Level</th>
                      <th className="py-2.5 px-3 md:w-[10%] text-center">Score</th>
                      <th className="py-2.5 px-3 md:w-[40%]">Detection Rationale</th>
                    </tr>
                  </thead>
                  <tbody className={`divide-y ${isDark ? 'divide-slate-800/80' : 'divide-slate-100'}`}>
                    {data?.attack_table.map((row, idx) => (
                      <tr key={idx} className={`transition ${isDark ? 'hover:bg-slate-800/40' : 'hover:bg-slate-50/80'}`}>
                        <td className={`py-2.5 px-3 font-semibold ${isDark ? 'text-slate-200' : 'text-slate-900'}`}>
                          {row.attack}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-block px-2 py-0.5 rounded font-mono font-bold text-[10px] border whitespace-nowrap ${
                              row.status === 'AUTO-DETECTED'
                                ? isDark ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-rose-50 text-rose-700 border-rose-200'
                                : row.status === 'SIMULATION'
                                ? isDark ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-amber-50 text-amber-700 border-amber-200'
                                : isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200'
                            }`}
                          >
                            {row.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-semibold">
                          <span className={
                            row.risk_score >= 60
                              ? isDark ? 'text-rose-400' : 'text-rose-700'
                              : isDark ? 'text-emerald-400' : 'text-emerald-700'
                          }>
                            {row.risk}
                          </span>
                        </td>
                        <td className={`py-2.5 px-3 font-mono font-bold text-center ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>
                          {row.risk_score}
                        </td>
                        <td className={`py-2.5 px-3 text-[11px] leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                          {row.reason}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </main>
        )}
      </div>

      {/* CBOM Modal */}
      <CbomModal
        cbom={data?.cbom}
        isOpen={cbomOpen}
        onClose={() => setCbomOpen(false)}
        isDark={isDark}
      />

      {/* Certificate Modal */}
      <CertificateModal
        cert={data?.certificate_analysis}
        isOpen={certModalOpen}
        onClose={() => setCertModalOpen(false)}
        isDark={isDark}
      />

      {/* Footer */}
      <footer className={`border-t py-3.5 text-center text-xs transition-colors duration-200 mt-6 ${
        isDark ? 'border-slate-800 bg-[#0d1322] text-slate-400' : 'border-slate-200 bg-white text-slate-500'
      }`}>
        Quantum Digital Signature Security Analyzer &bull; Quantum-Inspired Cyber Threat Detection for Digital Signature Security
      </footer>
    </div>
  );
}
