import React, { useState } from 'react';
import {
  FileCode,
  Shield,
  Key,
  Cpu,
  Lock,
  Download,
  Play,
  Zap,
  ArrowRight,
  CheckCircle2,
  Copy,
  Check,
  RefreshCw,
  Upload,
  Info,
  Layers,
  Sparkles
} from 'lucide-react';
import {
  QdsPackage,
  QdsSignatureAlgorithm,
  QdsQuantumProtocol
} from '../types';
import {
  createQdsPackage,
  downloadPackageFile,
  QDS_PRESET_TEMPLATES,
  QdsSignOptions
} from '../qdsPackageEngine';

interface QdsSigningEngineViewProps {
  onPackageGenerated: (pkg: QdsPackage) => void;
  onSendToVerify: (pkg: QdsPackage) => void;
  onSendToAttackLab: (pkg: QdsPackage) => void;
  theme: 'dark' | 'light';
}

export const QdsSigningEngineView: React.FC<QdsSigningEngineViewProps> = ({
  onPackageGenerated,
  onSendToVerify,
  onSendToAttackLab,
  theme
}) => {
  const [selectedPresetId, setSelectedPresetId] = useState<string>('defense-auth');
  const [filename, setFilename] = useState<string>('DoD_Directive_QuantumAuth_2026.pdf');
  const [fileContent, setFileContent] = useState<string>(QDS_PRESET_TEMPLATES[0].content);
  const [algorithm, setAlgorithm] = useState<QdsSignatureAlgorithm>('ML-DSA-65 (Dilithium3)');
  const [signerProfile, setSignerProfile] = useState<string>('alice');
  const [customSignerName, setCustomSignerName] = useState<string>('Dr. Alice Vance');
  const [customSignerRole, setCustomSignerRole] = useState<string>('Chief Cryptographic Officer');
  const [quantumProtocol, setQuantumProtocol] = useState<QdsQuantumProtocol>('BB84-Decoy-State');
  const [isSigning, setIsSigning] = useState<boolean>(false);
  const [signingStep, setSigningStep] = useState<string>('');
  const [generatedPackage, setGeneratedPackage] = useState<QdsPackage | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showRawJson, setShowRawJson] = useState<boolean>(false);

  const handleSelectPreset = (presetId: string) => {
    setSelectedPresetId(presetId);
    const p = QDS_PRESET_TEMPLATES.find(t => t.id === presetId);
    if (p) {
      setFilename(p.filename);
      setFileContent(p.content);
      setAlgorithm(p.algorithm);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    setSelectedPresetId('custom');

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setFileContent(text || '');
    };
    reader.readAsText(file);
  };

  const handleSignFile = async () => {
    if (!fileContent.trim()) return;
    setIsSigning(true);
    setSigningStep('Computing SHA-256 Digest...');

    await new Promise(r => setTimeout(r, 200));
    setSigningStep(`Generating ${algorithm} Digital Signature...`);

    await new Promise(r => setTimeout(r, 250));
    setSigningStep('Generating Cryptographic Nonce & Session ID...');

    await new Promise(r => setTimeout(r, 200));
    setSigningStep('Calibrating Simulated Quantum Channel Telemetry...');

    await new Promise(r => setTimeout(r, 250));
    setSigningStep('Assembling .QDS Security Package & Immutable Envelope...');

    let identity = customSignerName;
    let email = 'alice@quantum-vault.internal';
    let role = customSignerRole;
    let org = 'National Quantum Security Laboratory';

    if (signerProfile === 'bob') {
      identity = 'Bob Martinez';
      email = 'bob@finance-audit.internal';
      role = 'Senior Financial Officer';
      org = 'Federal Interbank Reserve';
    } else if (signerProfile === 'carol') {
      identity = 'Carol Danvers';
      email = 'carol@aerospace-sec.gov';
      role = 'Avionics Security Engineer';
      org = 'Space Defense Command';
    }

    const opts: QdsSignOptions = {
      filename,
      content: fileContent,
      algorithm,
      signerIdentity: identity,
      signerEmail: email,
      signerRole: role,
      signerOrg: org,
      quantumProtocol,
      qberBaseline: 1.25
    };

    const pkg = await createQdsPackage(opts);
    setGeneratedPackage(pkg);
    setIsSigning(false);
    setSigningStep('');
    onPackageGenerated(pkg);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 1800);
  };

  return (
    <div className="space-y-4">
      {/* Workflow Navigation Banner */}
      <div className={`p-4 rounded-lg border ${
        theme === 'light'
          ? 'bg-gradient-to-r from-blue-50 via-indigo-50 to-sky-50 border-blue-200'
          : 'bg-gradient-to-r from-[#0E172A] via-[#111C38] to-[#0D1E3A] border-[#1E293B]'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className={`text-xs font-bold uppercase tracking-wider ${theme === 'light' ? 'text-blue-900' : 'text-blue-400'}`}>
                Q-SHIELD Architectural Pipeline
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-blue-400/30 bg-blue-500/10 text-blue-600 dark:text-blue-300 font-semibold">
                STAGE 1: QDS SIGNING ENGINE
              </span>
            </div>
            <h2 className={`text-base font-bold mt-1 ${theme === 'light' ? 'text-gray-900' : 'text-white'}`}>
              Quantum Digital Signature Signing Engine
            </h2>
            <p className={`text-xs mt-0.5 max-w-3xl ${theme === 'light' ? 'text-gray-600' : 'text-gray-400'}`}>
              Transform any file into an immutable, authenticated <strong className="font-mono text-blue-600 dark:text-blue-400">.QDS security package</strong>.
              Bundles SHA-256 integrity, NIST Post-Quantum signatures, cryptographic nonces, active session tracking, and simulated quantum telemetry.
            </p>
          </div>

          <div className="flex items-center gap-1.5 text-[11px] font-mono shrink-0">
            <span className="px-2 py-1 rounded bg-black/10 dark:bg-white/10 font-medium">User File</span>
            <ArrowRight className="w-3.5 h-3.5 opacity-50" />
            <span className="px-2 py-1 rounded bg-blue-500/20 text-blue-600 dark:text-blue-400 font-bold">Signing Engine</span>
            <ArrowRight className="w-3.5 h-3.5 opacity-50" />
            <span className="px-2 py-1 rounded bg-black/10 dark:bg-white/10 font-medium">.QDS Package</span>
          </div>
        </div>

        {/* Cryptography Disclaimer */}
        <div className={`mt-3 p-2.5 rounded text-[11px] flex items-start gap-2 border ${
          theme === 'light'
            ? 'bg-white/80 border-blue-100 text-gray-700'
            : 'bg-black/30 border-[#1E293B] text-gray-300'
        }`}>
          <Info className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />
          <div className="leading-relaxed">
            <strong className="text-blue-600 dark:text-blue-400">NIST Standardized Framework: </strong>
            Clearly distinguishes <em>Classical Cryptography</em> (ECDSA, RSA-PSS), <em>NIST Post-Quantum Cryptography</em> (FIPS 204 ML-DSA Dilithium, FIPS 205 SPHINCS+, FIPS 206 Falcon), and <em>Quantum Security Simulation</em> (statevector entanglement and BB84 QBER channel bounds).
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* LEFT COLUMN: Input File & Content (7 Cols) */}
        <div className={`lg:col-span-7 p-4 rounded-lg border space-y-4 ${
          theme === 'light' ? 'bg-white border-gray-200' : 'bg-[#111827] border-[#1E293B]'
        }`}>
          {/* Preset Template Selector */}
          <div>
            <label className={`block text-xs font-bold uppercase tracking-wider mb-2 ${
              theme === 'light' ? 'text-gray-700' : 'text-gray-300'
            }`}>
              1. Select Artifact or Upload File
            </label>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
              {QDS_PRESET_TEMPLATES.map(p => (
                <button
                  key={p.id}
                  onClick={() => handleSelectPreset(p.id)}
                  className={`p-2.5 rounded border text-left transition cursor-pointer ${
                    selectedPresetId === p.id
                      ? theme === 'light'
                        ? 'border-blue-500 bg-blue-50/70 text-blue-900 shadow-xs'
                        : 'border-blue-500 bg-blue-500/10 text-blue-300 shadow-xs'
                      : theme === 'light'
                        ? 'border-gray-200 bg-gray-50/50 hover:bg-gray-100/70 text-gray-700'
                        : 'border-[#1E293B] bg-[#162032] hover:bg-[#1E293B] text-gray-300'
                  }`}
                >
                  <div className="text-xs font-semibold truncate">{p.name}</div>
                  <div className="text-[10px] text-gray-500 font-mono truncate mt-0.5">{p.filename}</div>
                  <div className="text-[10px] opacity-75 mt-1 line-clamp-1">{p.description}</div>
                </button>
              ))}
            </div>

            {/* Custom Upload Bar */}
            <div className="flex items-center gap-2">
              <label className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded border border-dashed cursor-pointer text-xs font-medium transition ${
                theme === 'light'
                  ? 'border-gray-300 bg-gray-50 hover:bg-blue-50/50 text-gray-700'
                  : 'border-[#1E293B] bg-[#131B2E] hover:bg-[#1E293B] text-gray-300'
              }`}>
                <Upload className="w-3.5 h-3.5 text-blue-500" />
                <span>Upload Custom Document (PDF, TXT, JSON, CSV)</span>
                <input type="file" onChange={handleFileUpload} className="hidden" />
              </label>

              <div className="w-48">
                <input
                  type="text"
                  value={filename}
                  onChange={(e) => setFilename(e.target.value)}
                  placeholder="Target filename..."
                  className={`w-full px-2.5 py-1.5 rounded border text-xs font-mono focus:outline-hidden ${
                    theme === 'light'
                      ? 'border-gray-300 bg-white text-gray-900 focus:border-blue-500'
                      : 'border-[#1E293B] bg-[#162032] text-white focus:border-blue-500'
                  }`}
                />
              </div>
            </div>
          </div>

          {/* File Content Workspace */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className={`text-xs font-bold uppercase tracking-wider ${
                theme === 'light' ? 'text-gray-700' : 'text-gray-300'
              }`}>
                Payload Content
              </label>
              <span className="text-[10px] font-mono text-gray-500">
                {new TextEncoder().encode(fileContent).length} bytes · {fileContent.split('\n').length} lines
              </span>
            </div>
            <textarea
              value={fileContent}
              onChange={(e) => setFileContent(e.target.value)}
              rows={11}
              className={`w-full p-3 rounded border text-xs font-mono focus:outline-hidden leading-relaxed resize-y ${
                theme === 'light'
                  ? 'border-gray-300 bg-gray-50 text-gray-900 focus:border-blue-500 focus:bg-white'
                  : 'border-[#1E293B] bg-[#0A0E17] text-gray-200 focus:border-blue-500'
              }`}
              placeholder="Paste or write original file payload..."
            />
          </div>
        </div>

        {/* RIGHT COLUMN: Cryptographic Profile & Signing Action (5 Cols) */}
        <div className={`lg:col-span-5 p-4 rounded-lg border space-y-4 flex flex-col justify-between ${
          theme === 'light' ? 'bg-white border-gray-200' : 'bg-[#111827] border-[#1E293B]'
        }`}>
          <div className="space-y-4">
            <h3 className={`text-xs font-bold uppercase tracking-wider ${
              theme === 'light' ? 'text-gray-700' : 'text-gray-300'
            }`}>
              2. Cryptographic & Quantum Profile
            </h3>

            {/* Signature Algorithm */}
            <div>
              <label className="block text-[11px] font-semibold text-gray-500 mb-1">
                Signature Algorithm (Post-Quantum & Classical)
              </label>
              <select
                value={algorithm}
                onChange={(e) => setAlgorithm(e.target.value as QdsSignatureAlgorithm)}
                className={`w-full px-2.5 py-1.5 rounded border text-xs font-medium focus:outline-hidden ${
                  theme === 'light'
                    ? 'border-gray-300 bg-white text-gray-900 focus:border-blue-500'
                    : 'border-[#1E293B] bg-[#162032] text-white focus:border-blue-500'
                }`}
              >
                <optgroup label="Post-Quantum Cryptography (NIST FIPS Standardized)">
                  <option value="ML-DSA-65 (Dilithium3)">ML-DSA-65 / Dilithium3 (NIST FIPS 204) — Recommended</option>
                  <option value="Falcon-512">Falcon-512 (NIST FIPS 206 Lattice Signature)</option>
                  <option value="SPHINCS+-SHA2-128s">SPHINCS+-SHA2-128s (NIST FIPS 205 Stateless Hash-Based)</option>
                </optgroup>
                <optgroup label="Classical Cryptography (Pre-Quantum)">
                  <option value="ECDSA-P256-SHA256">ECDSA-P256-SHA256 (NIST P-256 Curve)</option>
                  <option value="RSA-PSS-2048">RSA-PSS-2048 (RFC 8017 Probabilistic)</option>
                </optgroup>
              </select>
            </div>

            {/* Signer Identity */}
            <div>
              <label className="block text-[11px] font-semibold text-gray-500 mb-1">
                Authorized Signer Profile
              </label>
              <div className="grid grid-cols-3 gap-1.5 mb-2">
                {[
                  { id: 'alice', name: 'Dr. Alice Vance', role: 'Chief Crypto' },
                  { id: 'bob', name: 'Bob Martinez', role: 'Finance Officer' },
                  { id: 'carol', name: 'Carol Danvers', role: 'Avionics Eng' }
                ].map(s => (
                  <button
                    key={s.id}
                    onClick={() => {
                      setSignerProfile(s.id);
                      setCustomSignerName(s.name);
                    }}
                    className={`px-2 py-1.5 rounded border text-center transition cursor-pointer ${
                      signerProfile === s.id
                        ? theme === 'light'
                          ? 'border-blue-500 bg-blue-50 text-blue-900 font-semibold'
                          : 'border-blue-500 bg-blue-500/10 text-blue-300 font-semibold'
                        : theme === 'light'
                          ? 'border-gray-200 bg-gray-50 text-gray-700'
                          : 'border-[#1E293B] bg-[#162032] text-gray-400'
                    }`}
                  >
                    <div className="text-[11px] font-medium truncate">{s.name.split(' ')[0]}</div>
                    <div className="text-[9px] text-gray-500 truncate">{s.role}</div>
                  </button>
                ))}
              </div>

              <div className="space-y-1.5">
                <input
                  type="text"
                  value={customSignerName}
                  onChange={(e) => {
                    setCustomSignerName(e.target.value);
                    setSignerProfile('custom');
                  }}
                  placeholder="Signer Full Name..."
                  className={`w-full px-2.5 py-1.5 rounded border text-xs focus:outline-hidden ${
                    theme === 'light'
                      ? 'border-gray-300 bg-white text-gray-900 focus:border-blue-500'
                      : 'border-[#1E293B] bg-[#162032] text-white focus:border-blue-500'
                  }`}
                />
              </div>
            </div>

            {/* Quantum Protocol Telemetry */}
            <div>
              <label className="block text-[11px] font-semibold text-gray-500 mb-1">
                Quantum Channel Simulation Protocol
              </label>
              <select
                value={quantumProtocol}
                onChange={(e) => setQuantumProtocol(e.target.value as QdsQuantumProtocol)}
                className={`w-full px-2.5 py-1.5 rounded border text-xs font-medium focus:outline-hidden ${
                  theme === 'light'
                    ? 'border-gray-300 bg-white text-gray-900 focus:border-blue-500'
                    : 'border-[#1E293B] bg-[#162032] text-white focus:border-blue-500'
                }`}
              >
                <option value="BB84-Decoy-State">BB84 Decoy-State Protocol (QBER Baseline &lt; 2.0%)</option>
                <option value="E91-Entanglement">Ekert91 Entangled Photon Pairs (CHSH Bell Test)</option>
                <option value="Continuous-Variable-QDS">Continuous-Variable QDS (Gaussian Modulation)</option>
              </select>

              <div className={`mt-2 p-2 rounded text-[10px] font-mono grid grid-cols-3 gap-1 border ${
                theme === 'light' ? 'bg-gray-50 border-gray-200 text-gray-600' : 'bg-[#0E1526] border-[#1E293B] text-gray-400'
              }`}>
                <div>QBER Bound: &lt;11.0%</div>
                <div>Fidelity: 99.4%</div>
                <div>Decoy Yield: 98.5%</div>
              </div>
            </div>
          </div>

          {/* Action Button: Sign & Generate */}
          <div className="pt-2 border-t border-gray-200 dark:border-[#1E293B]">
            <button
              onClick={handleSignFile}
              disabled={isSigning || !fileContent.trim()}
              className={`w-full py-2.5 px-4 rounded-md font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer transition shadow-sm ${
                isSigning
                  ? 'bg-blue-400 text-white cursor-wait'
                  : 'bg-blue-600 hover:bg-blue-700 text-white shadow-blue-500/20'
              }`}
            >
              {isSigning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>{signingStep}</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-blue-200" />
                  <span>Sign &amp; Generate .QDS Package</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* GENERATED .QDS PACKAGE ARTIFACT CARD */}
      {generatedPackage && (
        <div className={`p-4 rounded-lg border space-y-4 animate-in fade-in duration-300 ${
          theme === 'light'
            ? 'bg-white border-green-300 shadow-md'
            : 'bg-[#0F172A] border-green-500/40 shadow-lg'
        }`}>
          {/* Header of Generated Package */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-gray-200 dark:border-[#1E293B]">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded bg-green-500/20 text-green-600 dark:text-green-400 flex items-center justify-center border border-green-500/30">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className={`text-sm font-bold ${theme === 'light' ? 'text-gray-900' : 'text-white'}`}>
                    {generatedPackage.original_artifact.filename.replace(/\.[^/.]+$/, '')}.qds
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-green-500/10 border border-green-500/30 text-green-600 dark:text-green-400 font-semibold">
                    IMMUTABLE SECURITY PACKAGE
                  </span>
                </div>
                <div className="text-[11px] text-gray-500 font-mono mt-0.5">
                  ID: {generatedPackage.package_id} · Created: {generatedPackage.created_at}
                </div>
              </div>
            </div>

            {/* Quick Action Buttons */}
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => onSendToVerify(generatedPackage)}
                className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer shadow-xs"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Verify Package Directly</span>
              </button>

              <button
                onClick={() => onSendToAttackLab(generatedPackage)}
                className="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer shadow-xs"
                title="Create an isolated copy and test against attack vectors (original remains untouched)"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Send to Attack Lab (Isolated Copy)</span>
              </button>

              <button
                onClick={() => downloadPackageFile(generatedPackage)}
                className={`px-3 py-1.5 rounded border text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer ${
                  theme === 'light'
                    ? 'border-gray-300 bg-white hover:bg-gray-100 text-gray-700'
                    : 'border-[#1E293B] bg-[#162032] hover:bg-[#1E293B] text-gray-200'
                }`}
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .QDS</span>
              </button>

              <button
                onClick={() => setShowRawJson(!showRawJson)}
                className={`px-2.5 py-1.5 rounded border text-xs font-mono transition cursor-pointer ${
                  theme === 'light'
                    ? 'border-gray-300 bg-gray-50 hover:bg-gray-100 text-gray-600'
                    : 'border-[#1E293B] bg-[#131B2E] hover:bg-[#1E293B] text-gray-400'
                }`}
              >
                {showRawJson ? 'Hide JSON' : '{ JSON }'}
              </button>
            </div>
          </div>

          {/* 8 Core Elements Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* 1. Original File */}
            <div className={`p-3 rounded border ${
              theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-[#162032] border-[#1E293B]'
            }`}>
              <div className="text-[10px] font-mono uppercase text-gray-500 font-semibold mb-1 flex items-center justify-between">
                <span>1. Original Artifact</span>
                <FileCode className="w-3.5 h-3.5 text-blue-500" />
              </div>
              <div className="text-xs font-bold truncate">{generatedPackage.original_artifact.filename}</div>
              <div className="text-[10px] font-mono text-gray-500 mt-0.5">
                {generatedPackage.original_artifact.file_size_formatted} · {generatedPackage.original_artifact.mime_type}
              </div>
            </div>

            {/* 2. SHA-256 Digest */}
            <div className={`p-3 rounded border ${
              theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-[#162032] border-[#1E293B]'
            }`}>
              <div className="text-[10px] font-mono uppercase text-gray-500 font-semibold mb-1 flex items-center justify-between">
                <span>2. SHA-256 Digest</span>
                <button
                  onClick={() => copyToClipboard(generatedPackage.cryptography.sha256, 'sha256')}
                  className="text-gray-400 hover:text-blue-500 cursor-pointer"
                  title="Copy SHA-256"
                >
                  {copiedField === 'sha256' ? <Check className="w-3 h-3 text-green-500" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <div className="text-[11px] font-mono truncate font-semibold text-emerald-600 dark:text-emerald-400">
                {generatedPackage.cryptography.sha256}
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-0.5">Pre-image collision resistant</div>
            </div>

            {/* 3. Digital Signature */}
            <div className={`p-3 rounded border ${
              theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-[#162032] border-[#1E293B]'
            }`}>
              <div className="text-[10px] font-mono uppercase text-gray-500 font-semibold mb-1 flex items-center justify-between">
                <span>3. Digital Signature</span>
                <Key className="w-3.5 h-3.5 text-indigo-500" />
              </div>
              <div className="text-xs font-semibold truncate text-indigo-600 dark:text-indigo-400">
                {generatedPackage.cryptography.signature_algorithm}
              </div>
              <div className="text-[10px] font-mono text-gray-500 truncate mt-0.5">
                {generatedPackage.cryptography.digital_signature.slice(0, 24)}...
              </div>
            </div>

            {/* 4. Nonce & Session */}
            <div className={`p-3 rounded border ${
              theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-[#162032] border-[#1E293B]'
            }`}>
              <div className="text-[10px] font-mono uppercase text-gray-500 font-semibold mb-1 flex items-center justify-between">
                <span>4. Nonce &amp; Session</span>
                <Lock className="w-3.5 h-3.5 text-amber-500" />
              </div>
              <div className="text-xs font-mono font-semibold truncate">
                {generatedPackage.cryptography.session_id}
              </div>
              <div className="text-[10px] font-mono text-gray-500 truncate mt-0.5">
                Nonce: {generatedPackage.cryptography.nonce.slice(0, 16)}...
              </div>
            </div>

            {/* 5. Signer Information */}
            <div className={`p-3 rounded border ${
              theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-[#162032] border-[#1E293B]'
            }`}>
              <div className="text-[10px] font-mono uppercase text-gray-500 font-semibold mb-1 flex items-center justify-between">
                <span>5. Signer Identity</span>
                <Shield className="w-3.5 h-3.5 text-blue-500" />
              </div>
              <div className="text-xs font-bold truncate">{generatedPackage.signer.identity}</div>
              <div className="text-[10px] text-gray-500 truncate mt-0.5">
                {generatedPackage.signer.role} · {generatedPackage.signer.organization}
              </div>
            </div>

            {/* 6. Public Key Certificate */}
            <div className={`p-3 rounded border ${
              theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-[#162032] border-[#1E293B]'
            }`}>
              <div className="text-[10px] font-mono uppercase text-gray-500 font-semibold mb-1 flex items-center justify-between">
                <span>6. PKI Credentials</span>
                <Key className="w-3.5 h-3.5 text-purple-500" />
              </div>
              <div className="text-[11px] font-mono font-semibold truncate">
                {generatedPackage.signer.key_fingerprint}
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-0.5">
                Serial: {generatedPackage.signer.certificate_serial} (Trusted)
              </div>
            </div>

            {/* 7. Quantum Security Evidence */}
            <div className={`p-3 rounded border ${
              theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-[#162032] border-[#1E293B]'
            }`}>
              <div className="text-[10px] font-mono uppercase text-gray-500 font-semibold mb-1 flex items-center justify-between">
                <span>7. Quantum Telemetry</span>
                <Cpu className="w-3.5 h-3.5 text-teal-500" />
              </div>
              <div className="text-xs font-semibold truncate text-teal-600 dark:text-teal-400">
                QBER: {generatedPackage.quantum_evidence.observed_qber.toFixed(2)}% (Optimal)
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-0.5">
                Fidelity: {(generatedPackage.quantum_evidence.quantum_state_fidelity * 100).toFixed(1)}% · {generatedPackage.quantum_evidence.channel_status}
              </div>
            </div>

            {/* 8. Immutable Envelope */}
            <div className={`p-3 rounded border ${
              theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-[#162032] border-[#1E293B]'
            }`}>
              <div className="text-[10px] font-mono uppercase text-gray-500 font-semibold mb-1 flex items-center justify-between">
                <span>8. Package Envelope</span>
                <Layers className="w-3.5 h-3.5 text-sky-500" />
              </div>
              <div className="text-[11px] font-mono font-semibold truncate text-sky-600 dark:text-sky-400">
                {generatedPackage.metadata.immutable_hash}
              </div>
              <div className="text-[10px] font-mono text-gray-500 mt-0.5">Spec: QDS-PACKAGE-v2.0</div>
            </div>
          </div>

          {/* JSON Inspector View */}
          {showRawJson && (
            <div className="pt-2">
              <div className="text-xs font-mono font-semibold text-gray-500 mb-1 flex items-center justify-between">
                <span>Canonical .QDS Package JSON Representation</span>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(generatedPackage, null, 2), 'json')}
                  className="text-xs text-blue-500 hover:underline flex items-center gap-1 cursor-pointer"
                >
                  <Copy className="w-3 h-3" />
                  <span>Copy JSON</span>
                </button>
              </div>
              <pre className={`p-3 rounded border text-[11px] font-mono overflow-x-auto max-h-72 leading-relaxed ${
                theme === 'light' ? 'bg-gray-900 text-gray-100' : 'bg-black text-gray-200 border-[#1E293B]'
              }`}>
                {JSON.stringify(generatedPackage, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
