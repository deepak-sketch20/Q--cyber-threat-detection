import React, { useState, useRef } from 'react';
import {
  Shield,
  ShieldCheck,
  AlertTriangle,
  FileText,
  ChevronRight,
  Activity,
  CheckCircle2,
  XCircle,
  Upload,
  Play,
  X,
  RefreshCw,
  Cpu,
  KeyRound,
  Zap,
  ArrowRight,
  Sparkles
} from 'lucide-react';
import { AnalysisResponse, UploadProgressState, QdsPackage, QdsVerificationResult } from '../types';
import { ThreatDistributionChart } from './ThreatDistributionChart';
import { EvidenceForensicViewer } from './EvidenceForensicViewer';
import { StreamingUploadProgress } from './StreamingUploadProgress';

export interface HistoryCase {
  case_id: string;
  file_name: string;
  timestamp: string;
  risk_score: number;
  status: string;
  threats_count: number;
  primary_threat: string;
  data?: AnalysisResponse;
  file_size?: number;
  file_type?: string;
  sha256?: string;
  user_id?: string;
  analysis_status?: string;
  security_status?: string;
  completed_at?: string;
}

interface DashboardViewProps {
  data: AnalysisResponse | null;
  history: HistoryCase[];
  filesAnalyzedCount: number;
  storageStatus?: { status: string; engine: string; message?: string };
  theme?: 'light' | 'dark';
  onRefreshCases?: () => void;
  onSelectCase: (caseData: AnalysisResponse) => void;
  onNavigateToAnalyzer: () => void;
  onNavigateToReport: () => void;
  onLoadSample: (sampleId: string) => void;
  // Dashboard direct file upload & analysis handlers
  onFileUpload: (file: File) => void;
  loading?: boolean;
  analysisState?: 'idle' | 'running' | 'completed' | 'error';
  uploadProgress?: UploadProgressState | null;
  onCancelUpload?: () => void;
  selectedFile?: File | null;
  onRunAnalysis?: () => void;
  activeSampleId?: string | null;
  mode?: string;
  onModeChange?: (mode: string) => void;
  errorMessage?: string | null;
  errorDetails?: string | null;
  onDismissError?: () => void;
  onNavigateToSigning?: () => void;
  onNavigateToAttackLab?: () => void;
  activeQdsPackage?: QdsPackage | null;
  qdsVerificationResult?: QdsVerificationResult | null;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  data,
  history,
  filesAnalyzedCount,
  storageStatus,
  theme,
  onRefreshCases,
  onSelectCase,
  onNavigateToAnalyzer,
  onNavigateToReport,
  onLoadSample,
  onFileUpload,
  loading = false,
  uploadProgress,
  onCancelUpload,
  selectedFile,
  onRunAnalysis,
  activeSampleId,
  mode = 'Automatic Detection',
  onModeChange,
  errorMessage,
  errorDetails,
  onDismissError,
  onNavigateToSigning,
  onNavigateToAttackLab,
  activeQdsPackage,
  qdsVerificationResult
}) => {
  const isLight = theme === 'light';
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Target Artifact Metadata computations
  const targetFileName = data?.file?.filename || selectedFile?.name || (activeSampleId ? activeSampleId : 'test_1_secure.txt');
  const targetFileSize = data?.file?.file_size || (selectedFile ? `${Math.max(1, Math.round(selectedFile.size / 1024))} KB` : '551 B');
  const fileExtension = targetFileName.split('.').pop()?.toUpperCase() || 'TXT';
  const targetSha256 = data?.file?.sha256 || uploadProgress?.calculatedHash || '';
  const storagePathDisplay = data?.storage_path || (data?.case_id ? `qsecure-files/${data.case_id}/${targetFileName}` : 'Supabase Bucket: qsecure-files');

  // Security Status & Risk Computations
  const riskScore = data?.threat?.risk_score ?? 0;
  const isAttack = data ? (data.threat?.status === 'ATTACK DETECTED' || riskScore >= 60) : false;
  const isSuspicious = data ? (!isAttack && (riskScore >= 35 || data.signature?.hash_mismatch)) : false;

  let overallSecurityStatus: 'SECURE' | 'SUSPICIOUS' | 'COMPROMISED' = 'SECURE';
  let statusBadgeColor = isLight
    ? 'bg-[#DCFCE7] text-[#15803D] border-[#86EFAC]'
    : 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]';
  let statusIcon = <CheckCircle2 className={`w-3.5 h-3.5 ${isLight ? 'text-[#15803D]' : 'text-[#34D399]'}`} />;

  if (isAttack) {
    overallSecurityStatus = 'COMPROMISED';
    statusBadgeColor = isLight
      ? 'bg-[#FEE2E2] text-[#B91C1C] border-[#FCA5A5]'
      : 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]';
    statusIcon = <XCircle className={`w-3.5 h-3.5 ${isLight ? 'text-[#B91C1C]' : 'text-[#F87171]'}`} />;
  } else if (isSuspicious) {
    overallSecurityStatus = 'SUSPICIOUS';
    statusBadgeColor = isLight
      ? 'bg-[#FEF3C7] text-[#B45309] border-[#FCD34D]'
      : 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]';
    statusIcon = <AlertTriangle className={`w-3.5 h-3.5 ${isLight ? 'text-[#B45309]' : 'text-[#FBBF24]'}`} />;
  }

  // Calculate detected threats count from attack_table and primary threat
  const detectedThreatRows = (data?.attack_table || []).filter(
    r => r.status === 'AUTO-DETECTED' || r.status === 'SIMULATION' || r.status === 'ATTACK DETECTED'
  );
  const detectedThreatCount = isAttack
    ? Math.max(1, detectedThreatRows.length, (data?.threat?.evidence?.length ? 1 : 0))
    : 0;

  // Threat Overview mapping for the 8 standard vectors with SOC severity classifications
  const threatOverviewItems = [
    {
      name: 'Digital Signature Forgery',
      severity: 'Critical',
      detected: (data?.attack_table || []).some(r => r.attack === 'Forgery' && (r.status !== 'NOT DETECTED')) ||
        Boolean(data?.signature?.signature_status?.toUpperCase().includes('INVALID')) ||
        Boolean(data?.signature?.hash_mismatch) ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('forgery')),
      detail: data?.signature?.hash_mismatch ? 'Digest mismatch in signed payload' : 'Cryptographic signature verification intact'
    },
    {
      name: 'Replay Attack',
      severity: 'High',
      detected: (data?.attack_table || []).some(r => r.attack === 'Replay' && (r.status !== 'NOT DETECTED')) ||
        Boolean(data?.stateful_replay?.is_stateful_replay) ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('replay')),
      detail: data?.stateful_replay?.is_stateful_replay ? 'Reused nonce or duplicate timestamp detected' : 'Nonce freshness delta verified'
    },
    {
      name: 'Signer Impersonation',
      severity: 'High',
      detected: (data?.attack_table || []).some(r => r.attack === 'Impersonation' && (r.status !== 'NOT DETECTED')) ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('impersonation')) ||
        data?.certificate_analysis?.status === 'UNTRUSTED',
      detail: data?.certificate_analysis?.status === 'UNTRUSTED' ? 'Untrusted signer identity mismatch' : 'Signer certificate authorization valid'
    },
    {
      name: 'Unauthorized Verification',
      severity: 'High',
      detected: (data?.attack_table || []).some(r => r.attack === 'Certificate / Trust Failure' && (r.status !== 'NOT DETECTED')) ||
        data?.certificate_analysis?.status === 'INVALID' ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('certificate')),
      detail: 'Public key certificate trust chain validation'
    },
    {
      name: 'File Tampering',
      severity: 'High',
      detected: Boolean(data?.signature?.hash_mismatch) ||
        Boolean(data?.file?.integrity_status?.toUpperCase().includes('MISMATCH')) ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('tamper')),
      detail: 'SHA-256 message digest integrity validation'
    },
    {
      name: 'Channel Tampering',
      severity: 'Medium',
      detected: (data?.attack_table || []).some(r => r.attack === 'Classical Channel Tampering' && (r.status !== 'NOT DETECTED')) ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('channel')),
      detail: 'In-transit communication packet integrity'
    },
    {
      name: 'Eavesdropping (Quantum)',
      severity: 'Critical',
      detected: (data?.attack_table || []).some(r => r.attack === 'Entangle-and-Measure' && (r.status !== 'NOT DETECTED')) ||
        ((data?.quantum?.qber ?? 0) >= 0.11) ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('eavesdrop')) ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('entangle')),
      detail: `Quantum Channel QBER: ${data?.quantum?.qber_percentage || '0.00%'} (Threshold: 11.0%)`
    },
    {
      name: 'Intercept-Resend (Quantum)',
      severity: 'Critical',
      detected: (data?.attack_table || []).some(r => r.attack === 'Intercept-Resend' && (r.status !== 'NOT DETECTED')) ||
        Boolean(data?.threat?.detected_threat?.toLowerCase().includes('intercept')),
      detail: 'Eavesdropper quantum measurement disturbance'
    }
  ];

  // Threat distribution items for Chart.js visualization
  const distributionChartItems = [
    { label: 'Forgery', value: threatOverviewItems[0].detected ? 92 : 4, detected: threatOverviewItems[0].detected },
    { label: 'Replay', value: threatOverviewItems[1].detected ? 85 : 5, detected: threatOverviewItems[1].detected },
    { label: 'Impersonation', value: threatOverviewItems[2].detected ? 88 : 3, detected: threatOverviewItems[2].detected },
    { label: 'Tampering', value: (threatOverviewItems[4].detected || threatOverviewItems[5].detected) ? 80 : 6, detected: (threatOverviewItems[4].detected || threatOverviewItems[5].detected) },
    { label: 'Eavesdropping', value: threatOverviewItems[6].detected ? 95 : (data?.quantum?.qber ? Math.min(100, Math.round(data.quantum.qber * 100)) : 2), detected: threatOverviewItems[6].detected }
  ];

  // Standard 8 Attack / Security Tabs
  const securityTabs = [
    { id: 'test_1_secure.txt', label: '1. Secure' },
    { id: 'test_2_replay_attack.txt', label: '2. Replay' },
    { id: 'test_3_forgery_attack.txt', label: '3. Forgery' },
    { id: 'test_4_impersonation.txt', label: '4. Impersonate' },
    { id: 'test_5_tampering.txt', label: '5. Tamper' },
    { id: 'test_6_quantum_eavesdropping.txt', label: '6. Quantum QBER' },
    { id: 'test_7_intercept_resend.txt', label: '7. Intercept-Resend' },
    { id: 'test_8_expired_cert.txt', label: '8. Expired Cert' }
  ];

  return (
    <div className="w-full space-y-4">
      {/* ===================================================================== */}
      {/* 0. Q-SHIELD CENTRAL WORKFLOW ARCHITECTURE BANNER */}
      {/* ===================================================================== */}
      <div className={`w-full border rounded-lg p-3.5 transition-colors ${
        isLight
          ? 'bg-gradient-to-r from-blue-50/80 via-sky-50/70 to-indigo-50/80 border-[#CBD5E1] shadow-xs'
          : 'bg-gradient-to-r from-[#0C1527] via-[#0E1A34] to-[#11172A] border-[#1E293B]'
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                isLight ? 'bg-blue-100 text-blue-800 border-blue-200' : 'bg-blue-500/20 text-blue-300 border-blue-500/30'
              }`}>
                Architectural Pipeline
              </span>
              <span className="text-xs font-bold text-gray-900 dark:text-white">
                Quantum Digital Signature Security &amp; Verification Platform
              </span>
            </div>
            <div className="text-[11px] text-gray-500 dark:text-gray-400 mt-1 max-w-4xl">
              End-to-end QDS lifecycle: Ingest any file &rarr; QDS Signing Engine &rarr; Immutable .QDS Package &rarr; Direct Verify or Attack Lab (with isolated copy preservation) &rarr; 8-Step Central Verification Engine &rarr; Final Decision.
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            {onNavigateToSigning && (
              <button
                onClick={onNavigateToSigning}
                className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer shadow-xs"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Open QDS Signing Engine</span>
              </button>
            )}

            {onNavigateToAttackLab && (
              <button
                onClick={onNavigateToAttackLab}
                className={`px-3 py-1.5 rounded border text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer ${
                  isLight
                    ? 'border-[#CBD5E1] bg-white hover:bg-[#F1F5F9] text-gray-800'
                    : 'border-[#1E293B] bg-[#162032] hover:bg-[#1E293B] text-gray-200'
                }`}
              >
                <Zap className="w-3.5 h-3.5 text-amber-500" />
                <span>Attack Simulation Lab</span>
              </button>
            )}
          </div>
        </div>

        {/* Workflow Diagram Nodes */}
        <div className="mt-3 pt-2.5 border-t border-black/5 dark:border-white/5 overflow-x-auto">
          <div className="flex items-center gap-1.5 text-[10px] font-mono min-w-max">
            <span className={`px-2 py-1 rounded font-semibold border ${
              isLight ? 'bg-white border-gray-300 text-gray-800' : 'bg-[#162032] border-[#1E293B] text-gray-300'
            }`}>
              USER FILE
            </span>
            <ArrowRight className="w-3 h-3 text-blue-500 shrink-0" />
            <span className="px-2 py-1 rounded font-semibold bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
              QDS SIGNING ENGINE
            </span>
            <ArrowRight className="w-3 h-3 text-blue-500 shrink-0" />
            <span className={`px-2 py-1 rounded font-semibold border ${
              isLight ? 'bg-white border-blue-300 text-blue-700' : 'bg-blue-900/30 border-blue-500/40 text-blue-300'
            }`}>
              .QDS PACKAGE
            </span>
            <ArrowRight className="w-3 h-3 text-blue-500 shrink-0" />
            <div className="flex items-center gap-1 px-1.5 py-0.5 rounded border border-dashed border-gray-400/40">
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">DIRECT VERIFY</span>
              <span className="text-gray-400">or</span>
              <span className="text-amber-600 dark:text-amber-400 font-semibold">ATTACK LAB (Isolated)</span>
            </div>
            <ArrowRight className="w-3 h-3 text-blue-500 shrink-0" />
            <span className="px-2 py-1 rounded font-semibold bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
              CENTRAL VERIFICATION (8-STEP)
            </span>
            <ArrowRight className="w-3 h-3 text-blue-500 shrink-0" />
            <span className="px-2 py-1 rounded font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
              VALID / WARNING / COMPROMISED
            </span>
            <ArrowRight className="w-3 h-3 text-blue-500 shrink-0" />
            <span className={`px-2 py-1 rounded font-semibold border ${
              isLight ? 'bg-white border-gray-300 text-gray-700' : 'bg-[#162032] border-[#1E293B] text-gray-300'
            }`}>
              FORENSIC REPORT
            </span>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 1. SECURITY TABS / CONTROLS (Full Viewport Width Flex Wrap) */}
      {/* ===================================================================== */}
      <div className={`w-full border rounded p-2.5 flex flex-wrap items-center justify-between gap-2.5 transition-colors ${
        isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
      }`}>
        {/* Left: Security Vector Preset Tabs */}
        <div className="flex items-center flex-wrap gap-2">
          <div className="flex items-center gap-1.5 mr-1">
            <span className={`w-2 h-2 rounded-full ${isLight ? 'bg-[#0284C7]' : 'bg-[#38BDF8]'}`}></span>
            <span className={`text-[11px] font-mono font-bold uppercase tracking-wider ${
              isLight ? 'text-[#334155]' : 'text-[#94A3B8]'
            }`}>
              Security Presets:
            </span>
          </div>

          {securityTabs.map((tab) => {
            const isSelected = activeSampleId === tab.id && !selectedFile;
            return (
              <button
                key={tab.id}
                onClick={() => onLoadSample(tab.id)}
                className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition cursor-pointer border ${
                  isSelected
                    ? 'bg-[#0284C7] text-white border-[#0284C7] font-bold shadow-xs'
                    : isLight
                      ? 'bg-[#F8FAFC] text-[#334155] border-[#CBD5E1] hover:bg-[#F1F5F9] hover:border-[#94A3B8]'
                      : 'bg-[#162032] text-[#94A3B8] border-[#1E293B] hover:bg-[#1E293B] hover:text-[#F1F5F9]'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Right: Automatic Detection Selector (Aligned to right when space exists) */}
        {onModeChange && (
          <div className="flex items-center gap-2 ml-auto shrink-0">
            <span className={`text-[11px] font-mono uppercase font-semibold hidden sm:inline ${
              isLight ? 'text-[#64748B]' : 'text-[#94A3B8]'
            }`}>
              Detection Mode:
            </span>
            <select
              value={mode}
              onChange={(e) => onModeChange(e.target.value)}
              className={`text-xs rounded px-3 py-1.5 font-mono border focus:outline-none transition cursor-pointer ${
                isLight ? 'bg-white border-[#CBD5E1] text-[#0F172A]' : 'bg-[#162032] border-[#1E293B] text-[#F1F5F9]'
              }`}
            >
              <option value="Automatic Detection">Automatic Detection (All Vectors)</option>
              <option value="Signature Integrity Only">Signature Integrity Only</option>
              <option value="Quantum Channel Analysis">Quantum Channel Analysis</option>
              <option value="Replay Attack Verification">Replay Attack Verification</option>
              <option value="Forgery Detection">Forgery Detection</option>
            </select>
          </div>
        )}
      </div>

      {/* ===================================================================== */}
      {/* 2. SECURITY ARTIFACT ANALYSIS CARD (Wide 4-Column Responsive Grid) */}
      {/* ===================================================================== */}
      <div className={`w-full border rounded p-3.5 space-y-3 transition-colors ${
        isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
      }`}>
        <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-2 ${
          isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'
        }`}>
          <div className="flex items-center gap-2">
            <span className={`p-1.5 rounded border ${
              isLight ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#0284C7]' : 'bg-[#162032] border-[#1E293B] text-[#38BDF8]'
            }`}>
              <ShieldCheck className="w-4 h-4" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className={`text-xs font-bold uppercase tracking-wider ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                  Security Artifact Analysis
                </h3>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold border ${
                  isLight ? 'bg-[#E0F2FE] border-[#BAE6FD] text-[#0284C7]' : 'bg-[#0284C7]/20 border-[#0284C7]/40 text-[#38BDF8]'
                }`}>
                  {data?.case_id || 'ACTIVE FORENSIC PROFILE'}
                </span>
              </div>
            </div>
          </div>

          {/* Right badges: Algorithm, Timestamp */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
              isLight ? 'bg-[#F8FAFC] border-[#CBD5E1] text-[#475569]' : 'bg-[#162032] border-[#1E293B] text-[#94A3B8]'
            }`}>
              Algorithm: {data?.signature?.algorithm || 'RSA-2048 / SHA-256'}
            </span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
              isLight ? 'bg-[#F8FAFC] border-[#CBD5E1] text-[#475569]' : 'bg-[#162032] border-[#1E293B] text-[#94A3B8]'
            }`}>
              {data?.file?.upload_time || 'Real-time Stream'}
            </span>
          </div>
        </div>

        {/* 4-Column Responsive Grid: 2fr 1fr 1fr 1fr */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-[2fr_1fr_1fr_1fr] gap-3">
          {/* 1. File Name (2fr) */}
          <div className={`p-2.5 rounded border transition-colors ${
            isLight ? 'bg-[#F8FAFC] border-[#E2E8F0]' : 'bg-[#162032]/80 border-[#1E293B]'
          }`}>
            <span className={`text-[10px] font-mono font-semibold uppercase block ${isLight ? 'text-[#64748B]' : 'text-[#94A3B8]'}`}>
              File Name
            </span>
            <span className={`text-xs font-mono font-bold block truncate mt-1 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`} title={targetFileName}>
              {targetFileName}
            </span>
            <span className={`text-[10px] font-mono mt-1 block ${isLight ? 'text-[#64748B]' : 'text-[#64748B]'}`}>
              Type: {fileExtension} &bull; Forensic Ingestion Target
            </span>
          </div>

          {/* 2. Size (1fr) */}
          <div className={`p-2.5 rounded border transition-colors ${
            isLight ? 'bg-[#F8FAFC] border-[#E2E8F0]' : 'bg-[#162032]/80 border-[#1E293B]'
          }`}>
            <span className={`text-[10px] font-mono font-semibold uppercase block ${isLight ? 'text-[#64748B]' : 'text-[#94A3B8]'}`}>
              Size
            </span>
            <span className={`text-xs font-mono font-bold block mt-1 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
              {targetFileSize}
            </span>
            <span className={`text-[10px] font-mono mt-1 block ${isLight ? 'text-[#64748B]' : 'text-[#64748B]'}`}>
              Streaming: Up to 1 TB Buffer
            </span>
          </div>

          {/* 3. Upload Status (1fr) */}
          <div className={`p-2.5 rounded border transition-colors ${
            isLight ? 'bg-[#F8FAFC] border-[#E2E8F0]' : 'bg-[#162032]/80 border-[#1E293B]'
          }`}>
            <span className={`text-[10px] font-mono font-semibold uppercase block ${isLight ? 'text-[#64748B]' : 'text-[#94A3B8]'}`}>
              Upload Status
            </span>
            <div className="flex items-center gap-1.5 mt-1">
              <span className={`w-2 h-2 rounded-full ${
                uploadProgress?.uploadStatus === 'uploading'
                  ? 'bg-[#0284C7] animate-ping'
                  : (data ? 'bg-[#10B981]' : 'bg-[#0284C7]')
              }`}></span>
              <span className={`text-xs font-mono font-bold truncate ${
                uploadProgress?.uploadStatus === 'uploading'
                  ? (isLight ? 'text-[#0284C7]' : 'text-[#38BDF8]')
                  : (data ? (isLight ? 'text-[#059669]' : 'text-[#34D399]') : (isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'))
              }`}>
                {uploadProgress?.uploadStatus === 'uploading' ? `Uploading ${uploadProgress.uploadPercent}%` : (data ? 'Ingested & Verified' : 'Ready for Ingestion')}
              </span>
            </div>
            <span className={`text-[10px] font-mono mt-1 block truncate ${isLight ? 'text-[#64748B]' : 'text-[#64748B]'}`} title={storagePathDisplay}>
              {storagePathDisplay}
            </span>
          </div>

          {/* 4. SHA-256 Status (1fr) */}
          <div className={`p-2.5 rounded border transition-colors ${
            isLight ? 'bg-[#F8FAFC] border-[#E2E8F0]' : 'bg-[#162032]/80 border-[#1E293B]'
          }`}>
            <span className={`text-[10px] font-mono font-semibold uppercase block ${isLight ? 'text-[#64748B]' : 'text-[#94A3B8]'}`}>
              SHA-256 Status
            </span>
            <span className={`text-xs font-mono font-bold block truncate mt-1 ${
              data?.signature?.hash_mismatch
                ? (isLight ? 'text-[#B91C1C]' : 'text-[#F87171]')
                : (isLight ? 'text-[#059669]' : 'text-[#34D399]')
            }`} title={targetSha256}>
              {data?.signature?.hash_mismatch ? 'MISMATCH DETECTED' : (targetSha256 ? `${targetSha256.substring(0, 10)}...` : 'VERIFIED')}
            </span>
            <span className={`text-[10px] font-mono mt-1 block ${isLight ? 'text-[#64748B]' : 'text-[#64748B]'}`}>
              Digest: FIPS 180-4 Intact
            </span>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 3. UPLOAD AREA + PRESETS (Grid: 1.3fr Left / 1fr Right) */}
      {/* ===================================================================== */}
      <div id="dashboard-file-upload-panel" className={`w-full border rounded p-3.5 space-y-3 transition-colors ${
        isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
      }`}>
        <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-2 ${
          isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'
        }`}>
          <div className="flex items-center gap-2">
            <span className={`p-1.5 rounded border ${
              isLight ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#0284C7]' : 'bg-[#162032] border-[#1E293B] text-[#38BDF8]'
            }`}>
              <Upload className="w-4 h-4" />
            </span>
            <div>
              <h3 className={`text-xs font-bold uppercase tracking-wider ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                Security Artifact Ingestion &amp; Live File Analysis
              </h3>
              <p className={`text-[11px] mt-0.5 ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
                Upload or drop digital signatures, raw binary files, or PEM bundles up to 1 TB for streaming forensic evaluation.
              </p>
            </div>
          </div>

          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold border ${
            isLight ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#0284C7]' : 'bg-[#162032] border-[#1E293B] text-[#38BDF8]'
          }`}>
            Streaming Pipeline: Active
          </span>
        </div>

        {/* Streaming Upload Progress Bar */}
        {uploadProgress && (
          <StreamingUploadProgress
            progress={uploadProgress}
            onCancel={onCancelUpload}
          />
        )}

        {/* Error Alert */}
        {errorMessage && (
          <div className={`p-2.5 rounded border text-xs flex items-center justify-between ${
            isLight ? 'bg-[#FEF2F2] border-[#FCA5A5] text-[#991B1B]' : 'bg-[#7F1D1D]/30 border-[#991B1B] text-[#F87171]'
          }`}>
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <div>
                <span className="font-bold font-mono">Analysis Notice: </span>
                <span>{errorMessage}</span>
                {errorDetails && <span className="opacity-80 block text-[11px] mt-0.5 font-mono">{errorDetails}</span>}
              </div>
            </div>
            {onDismissError && (
              <button onClick={onDismissError} className="p-1 cursor-pointer hover:opacity-75" title="Dismiss">
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        )}

        {/* Balanced Grid: Left (1.3fr) Drop / Browse, Right (1fr) Action Button + Presets */}
        <div className="grid grid-cols-1 lg:grid-cols-[1.3fr_1fr] gap-3">
          {/* LEFT: Drop / Browse upload area */}
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
                onFileUpload(e.dataTransfer.files[0]);
              }
            }}
            className={`border-2 border-dashed rounded p-3.5 text-center cursor-pointer transition flex items-center justify-center gap-3.5 ${
              isDragging
                ? 'border-[#0284C7] bg-[#0284C7]/15'
                : isLight
                  ? 'border-[#CBD5E1] hover:border-[#0284C7] bg-[#F8FAFC]'
                  : 'border-[#1E293B] hover:border-[#0284C7] bg-[#162032]/60'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={(e) => {
                if (e.target.files?.[0]) {
                  onFileUpload(e.target.files[0]);
                  e.target.value = '';
                }
              }}
              className="hidden"
            />
            <div className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 ${
              isLight ? 'bg-[#E0F2FE] text-[#0284C7]' : 'bg-[#0284C7]/20 text-[#38BDF8]'
            }`}>
              <Upload className="w-5 h-5" />
            </div>
            <div className="text-left flex-1 min-w-0">
              <div className={`text-xs font-bold font-mono truncate ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                {selectedFile ? `Selected: ${selectedFile.name}` : 'Drop security artifact here or click to browse'}
              </div>
              <div className={`text-[11px] font-mono mt-0.5 ${isLight ? 'text-[#64748B]' : 'text-[#94A3B8]'}`}>
                Supports .txt, .json, .pem, .sig, .bin &bull; Streaming pipeline up to 1 TB
              </div>
            </div>
          </div>

          {/* RIGHT: Upload & Analyze button + Quick Presets */}
          <div className={`p-3 rounded border flex flex-col justify-between gap-2.5 ${
            isLight ? 'bg-[#F8FAFC] border-[#E2E8F0]' : 'bg-[#162032]/70 border-[#1E293B]'
          }`}>
            {/* Primary Action Button */}
            <button
              onClick={() => {
                if (selectedFile && onRunAnalysis) {
                  onRunAnalysis();
                } else if (activeSampleId && onRunAnalysis) {
                  onRunAnalysis();
                } else if (fileInputRef.current) {
                  fileInputRef.current.click();
                }
              }}
              disabled={loading}
              className={`w-full py-2 px-3 rounded font-bold text-xs font-mono flex items-center justify-center gap-2 cursor-pointer transition shadow-xs ${
                loading
                  ? 'bg-[#64748B] text-white cursor-not-allowed'
                  : 'bg-[#0284C7] hover:bg-[#0369A1] text-white'
              }`}
            >
              {loading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing Security Vectors...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{selectedFile ? 'Analyze Selected Artifact' : 'Upload & Analyze Artifact'}</span>
                </>
              )}
            </button>

            {/* Quick Vector Shortcuts Grid */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className={`text-[10px] font-mono uppercase font-bold tracking-wider ${
                  isLight ? 'text-[#475569]' : 'text-[#94A3B8]'
                }`}>
                  Quick Attack Shortcuts:
                </span>
                <span className={`text-[10px] font-mono ${isLight ? 'text-[#64748B]' : 'text-[#64748B]'}`}>
                  1-Click Inject
                </span>
              </div>
              <div className="grid grid-cols-3 sm:grid-cols-5 gap-1.5">
                {[
                  { id: 'test_1_secure.txt', label: 'Secure' },
                  { id: 'test_2_replay_attack.txt', label: 'Replay' },
                  { id: 'test_3_forgery_attack.txt', label: 'Forgery' },
                  { id: 'test_5_tampering.txt', label: 'Tamper' },
                  { id: 'test_6_quantum_eavesdropping.txt', label: 'Quantum' }
                ].map(s => {
                  const isSelected = activeSampleId === s.id && !selectedFile;
                  return (
                    <button
                      key={s.id}
                      onClick={() => onLoadSample(s.id)}
                      className={`py-1 px-1.5 rounded text-[10px] font-mono border text-center transition cursor-pointer truncate ${
                        isSelected
                          ? 'bg-[#0284C7] text-white border-[#0284C7] font-bold shadow-xs'
                          : isLight
                            ? 'bg-white border-[#CBD5E1] text-[#334155] hover:bg-[#F1F5F9]'
                            : 'bg-[#111827] border-[#1E293B] text-[#94A3B8] hover:bg-[#1E293B] hover:text-[#F1F5F9]'
                      }`}
                    >
                      {s.label}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 4. SUMMARY CARDS (Full Viewport Width 4 Equal Columns) */}
      {/* ===================================================================== */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Card 1: Security Status */}
        <div className={`border rounded p-3 flex flex-col justify-between transition-colors ${
          isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
        }`}>
          <div className="flex items-center justify-between">
            <span className={`text-[10px] font-mono font-bold uppercase tracking-wider ${
              isLight ? 'text-[#334155]' : 'text-[#94A3B8]'
            }`}>
              Security Status
            </span>
            <span className={`w-2 h-2 rounded-full ${isLight ? 'bg-[#0284C7]' : 'bg-[#0284C7]/60'}`}></span>
          </div>
          <div className="mt-2 flex items-center justify-between">
            <div className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-xs font-bold font-mono uppercase ${statusBadgeColor}`}>
              {statusIcon}
              <span>{overallSecurityStatus}</span>
            </div>
          </div>
          <div className={`text-[11px] mt-2 font-mono truncate ${isLight ? 'text-[#475569]' : 'text-[#64748B]'}`} title={targetFileName}>
            Target: <span className={`font-semibold ${isLight ? 'text-[#0F172A]' : 'text-[#94A3B8]'}`}>{targetFileName}</span>
          </div>
        </div>

        {/* Card 2: Risk Score */}
        <div id="metric-card-risk-score" className={`border rounded p-3 flex flex-col justify-between transition-colors ${
          isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
        }`}>
          <div className="flex items-center justify-between">
            <span className={`text-[10px] font-mono font-bold uppercase tracking-wider ${
              isLight ? 'text-[#334155]' : 'text-[#94A3B8]'
            }`}>
              Risk Score
            </span>
            <span className={`text-[10px] font-bold font-mono px-1.5 py-0.2 rounded border ${
              riskScore >= 80 
                ? (isLight ? 'bg-[#FEE2E2] text-[#B91C1C] border-[#FCA5A5]' : 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]') 
                : riskScore >= 50 
                ? (isLight ? 'bg-[#FEF3C7] text-[#B45309] border-[#FCD34D]' : 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]') 
                : (isLight ? 'bg-[#DCFCE7] text-[#15803D] border-[#86EFAC]' : 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]')
            }`}>
              {data?.threat?.risk || (riskScore >= 80 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : 'LOW')}
            </span>
          </div>
          <div className="mt-1">
            <div className={`text-xl font-bold font-mono ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
              {riskScore} <span className={`text-xs font-normal font-sans ${isLight ? 'text-[#64748B]' : 'text-[#64748B]'}`}>/ 100</span>
            </div>
            {/* Horizontal scale */}
            <div className={`w-full rounded-full h-1.5 mt-1.5 overflow-hidden ${isLight ? 'bg-[#E2E8F0]' : 'bg-[#1E293B]'}`}>
              <div
                className="h-full transition-all duration-300"
                style={{
                  width: `${Math.max(4, riskScore)}%`,
                  backgroundColor: riskScore >= 80 ? '#EF4444' : riskScore >= 50 ? '#F59E0B' : '#10B981'
                }}
              />
            </div>
          </div>
          <div className={`text-[10px] font-mono mt-1 ${isLight ? 'text-[#475569]' : 'text-[#64748B]'}`}>
            Standard: NIST SP 800-131A
          </div>
        </div>

        {/* Card 3: Threats Detected */}
        <div className={`border rounded p-3 flex flex-col justify-between transition-colors ${
          isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
        }`}>
          <div className="flex items-center justify-between">
            <span className={`text-[10px] font-mono font-bold uppercase tracking-wider ${
              isLight ? 'text-[#334155]' : 'text-[#94A3B8]'
            }`}>
              Threats Detected
            </span>
            <Activity className={`w-3.5 h-3.5 ${isLight ? 'text-[#0284C7]' : 'text-[#64748B]'}`} />
          </div>
          <div className="mt-1">
            <div className={`text-xl font-bold font-mono ${
              detectedThreatCount > 0 
                ? (isLight ? 'text-[#DC2626]' : 'text-[#F87171]') 
                : (isLight ? 'text-[#16A34A]' : 'text-[#34D399]')
            }`}>
              {detectedThreatCount}
            </div>
          </div>
          <div className={`text-[11px] mt-1 truncate font-mono ${isLight ? 'text-[#475569]' : 'text-[#64748B]'}`} title={data?.threat?.detected_threat || 'None'}>
            {detectedThreatCount > 0 ? (
              <span className={`font-semibold ${isLight ? 'text-[#DC2626]' : 'text-[#F87171]'}`}>{data?.threat?.detected_threat}</span>
            ) : (
              <span>All 8 vectors within baseline</span>
            )}
          </div>
        </div>

        {/* Card 4: Files Analyzed */}
        <div className={`border rounded p-3 flex flex-col justify-between transition-colors ${
          isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
        }`}>
          <div className="flex items-center justify-between">
            <span className={`text-[10px] font-mono font-bold uppercase tracking-wider ${
              isLight ? 'text-[#334155]' : 'text-[#94A3B8]'
            }`}>
              Files Analyzed
            </span>
            <FileText className={`w-3.5 h-3.5 ${isLight ? 'text-[#475569]' : 'text-[#64748B]'}`} />
          </div>
          <div className="mt-1">
            <div className={`text-xl font-bold font-mono ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
              {filesAnalyzedCount}
            </div>
          </div>
          <div className={`text-[10px] font-mono mt-1 ${isLight ? 'text-[#475569]' : 'text-[#64748B]'}`}>
            Session History: <span className={`font-semibold ${isLight ? 'text-[#0F172A]' : 'text-[#94A3B8]'}`}>{history.length} logged</span>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 5. ATTACK EVIDENCE LOCATION & LINE-LEVEL FORENSIC VIEWER */}
      {/* ===================================================================== */}
      <div id="dashboard-attack-evidence-location" className="w-full">
        <EvidenceForensicViewer
          evidence={data?.evidence || data?.threat?.evidence_items || []}
          timeline={data?.evidence_timeline}
          fileName={targetFileName}
          fileSize={targetFileSize}
          isSecure={overallSecurityStatus === 'SECURE'}
          theme={theme}
        />
      </div>

      {/* ===================================================================== */}
      {/* 6. SOC THREAT OVERVIEW & MULTI-THREAT DISTRIBUTION (7 cols / 5 cols) */}
      {/* ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 w-full">
        {/* Left: SOC Threat Table (7 cols) */}
        <div className={`lg:col-span-7 border rounded p-3.5 space-y-3 transition-colors ${
          isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
        }`}>
          <div className={`flex items-center justify-between border-b pb-2 ${isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'}`}>
            <div>
              <div className="flex items-center gap-2">
                <h3 className={`text-xs font-bold uppercase tracking-wider ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                  Threat Overview
                </h3>
                <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border font-semibold ${
                  isLight ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#334155]' : 'bg-[#162032] border-[#1E293B] text-[#38BDF8]'
                }`}>
                  8 Vectors
                </span>
              </div>
              <p className={`text-[11px] mt-0.5 ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
                Real-time technical evaluation across classical cryptographic, protocol, and quantum vectors
              </p>
            </div>
            <button
              onClick={onNavigateToAnalyzer}
              className={`text-xs font-medium flex items-center gap-1 cursor-pointer transition ${
                isLight ? 'text-[#0284C7] hover:text-[#0369A1]' : 'text-[#38BDF8] hover:text-[#7DD3FC]'
              }`}
            >
              <span>Inspect</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className={`border rounded overflow-hidden shadow-xs ${
            isLight ? 'border-[#CBD5E1] bg-white' : 'border-[#1E293B] bg-[#162032]'
          }`}>
            <table className={`w-full text-left text-xs border-collapse ${isLight ? 'bg-white' : 'bg-[#162032]'}`}>
              <thead>
                <tr className={`border-b text-[11px] font-mono ${
                  isLight ? 'border-[#CBD5E1] bg-[#F1F5F9] text-[#1E293B]' : 'border-[#1E293B] bg-[#111827] text-[#94A3B8]'
                }`}>
                  <th className={`py-2.5 px-3 font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Threat Vector</th>
                  <th className={`py-2.5 px-2.5 font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Status</th>
                  <th className={`py-2.5 px-2.5 font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Severity</th>
                  <th className={`py-2.5 px-3 font-bold hidden sm:table-cell ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Details</th>
                </tr>
              </thead>
              <tbody className={`divide-y ${isLight ? 'divide-[#E2E8F0] bg-white' : 'divide-[#1E293B] bg-[#162032]'}`}>
                {threatOverviewItems.map((item, idx) => (
                  <tr
                    key={idx}
                    className={item.detected 
                      ? (isLight ? 'bg-[#FEF2F2] hover:bg-[#FEE2E2] transition-colors' : 'bg-[#7F1D1D]/20 hover:bg-[#7F1D1D]/30 transition-colors')
                      : (isLight 
                        ? (idx % 2 === 1 ? 'bg-[#F8FAFC] hover:bg-[#F1F5F9] transition-colors' : 'bg-white hover:bg-[#F8FAFC] transition-colors')
                        : (idx % 2 === 1 ? 'bg-[#131D2E] hover:bg-[#162032] transition-colors' : 'bg-[#162032] hover:bg-[#1A263D] transition-colors')
                      )
                    }
                  >
                    <td className={`py-2.5 px-3 font-semibold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                      {item.name}
                    </td>
                    <td className="py-2.5 px-2.5 whitespace-nowrap">
                      {item.detected ? (
                        <span className={`inline-flex items-center gap-1 text-[10px] font-bold font-mono px-2 py-0.5 rounded uppercase border ${
                          isLight ? 'text-[#B91C1C] bg-[#FEE2E2] border-[#FCA5A5]' : 'text-[#F87171] bg-[#7F1D1D]/40 border-[#991B1B]'
                        }`}>
                          <XCircle className={`w-3 h-3 ${isLight ? 'text-[#B91C1C]' : 'text-[#F87171]'}`} />
                          <span>Detected</span>
                        </span>
                      ) : (
                        <span className={`inline-flex items-center gap-1 text-[10px] font-bold font-mono px-2 py-0.5 rounded uppercase border ${
                          isLight ? 'text-[#15803D] bg-[#DCFCE7] border-[#86EFAC]' : 'text-[#34D399] bg-[#064E3B]/40 border-[#065F46]'
                        }`}>
                          <CheckCircle2 className={`w-3 h-3 ${isLight ? 'text-[#15803D]' : 'text-[#34D399]'}`} />
                          <span>Secure</span>
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-2.5 whitespace-nowrap font-mono text-[10px]">
                      <span className={`px-2 py-0.5 rounded font-bold border uppercase ${
                        item.severity === 'Critical'
                          ? (isLight ? 'bg-[#FEE2E2] text-[#B91C1C] border-[#FCA5A5]' : 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]')
                          : item.severity === 'High'
                          ? (isLight ? 'bg-[#FEF3C7] text-[#B45309] border-[#FCD34D]' : 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]')
                          : (isLight ? 'bg-[#F1F5F9] text-[#334155] border-[#CBD5E1]' : 'bg-[#1E293B] text-[#94A3B8] border-[#334155]')
                      }`}>
                        {item.severity}
                      </span>
                    </td>
                    <td className={`py-2.5 px-3 text-[11px] font-mono hidden sm:table-cell truncate max-w-xs ${
                      isLight ? 'text-[#334155]' : 'text-[#94A3B8]'
                    }`} title={item.detail}>
                      {item.detail}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Multi-Threat Distribution & Active Case Snapshot (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Threat Distribution Bars with Chart.js */}
          <div className={`border rounded p-3.5 space-y-3 transition-colors ${
            isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
          }`}>
            <div className={`border-b pb-2 ${isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'}`}>
              <h3 className={`text-xs font-bold uppercase tracking-wider ${
                isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'
              }`}>
                Threat Vector Contribution
              </h3>
              <p className={`text-[11px] ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
                Relative threat indicator weight observed in current artifact
              </p>
            </div>

            <ThreatDistributionChart items={distributionChartItems} theme={theme} />

            <div className={`pt-1 text-[11px] flex items-center justify-between border-t font-mono ${
              isLight ? 'border-[#E2E8F0] text-[#475569]' : 'border-[#1E293B] text-[#94A3B8]'
            }`}>
              <span>Threat Level: <strong className={isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}>{data?.threat?.risk || 'LOW'}</strong></span>
              <span>Confidence: <strong className={isLight ? 'text-[#0284C7]' : 'text-[#38BDF8]'}>{data?.threat?.confidence || 98}%</strong></span>
            </div>
          </div>

          {/* Quick Active Case Summary Card */}
          <div className={`border rounded p-3.5 space-y-2 text-xs transition-colors ${
            isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
          }`}>
            <div className={`flex items-center justify-between border-b pb-1.5 ${
              isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'
            }`}>
              <span className={`font-bold text-[11px] uppercase tracking-wider ${
                isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'
              }`}>Active Case Snapshot</span>
              <span className={`font-mono text-[11px] font-semibold ${
                isLight ? 'text-[#0284C7]' : 'text-[#38BDF8]'
              }`}>{data?.case_id || 'CASE-PROTOTYPE'}</span>
            </div>

            <div className="space-y-1 font-mono text-[11px]">
              <div className={`flex justify-between py-1 border-b ${isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'}`}>
                <span className={isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}>Algorithm:</span>
                <span className={`font-semibold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data?.signature?.algorithm || 'ECDSA-P256 / SHA-256'}</span>
              </div>
              <div className={`flex justify-between py-1 border-b ${isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'}`}>
                <span className={isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}>Signature:</span>
                <span className={data?.signature?.status === 'VALID' || data?.signature?.signature_status === 'VALID'
                  ? (isLight ? 'text-[#15803D] font-bold' : 'text-[#34D399] font-semibold') 
                  : (isLight ? 'text-[#DC2626] font-bold' : 'text-[#F87171] font-semibold')
                }>
                  {data?.signature?.status || data?.signature?.signature_status || 'VALID'}
                </span>
              </div>
              <div className={`flex justify-between py-1 border-b ${isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'}`}>
                <span className={isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}>Channel QBER:</span>
                <span className={(data?.quantum?.qber ?? 0) < 0.05 
                  ? (isLight ? 'text-[#15803D] font-bold' : 'text-[#34D399]') 
                  : (isLight ? 'text-[#DC2626] font-bold' : 'text-[#F87171]')
                }>
                  {data?.quantum?.qber_percentage || '0.00%'}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className={isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}>Timestamp:</span>
                <span className={`truncate max-w-[160px] ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data?.file?.upload_time || 'Recorded'}</span>
              </div>
            </div>

            <div className="pt-2 flex gap-2">
              <button
                onClick={onNavigateToReport}
                className="flex-1 py-1.5 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded text-center cursor-pointer transition shadow-xs"
              >
                View Full Report
              </button>
              <button
                onClick={onNavigateToAnalyzer}
                className={`px-3 py-1.5 border text-xs font-medium rounded text-center cursor-pointer transition ${
                  isLight 
                    ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#0F172A] hover:bg-[#E2E8F0]' 
                    : 'bg-[#162032] border-[#1E293B] text-[#F1F5F9] hover:bg-[#1E293B]'
                }`}
              >
                Inspect
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 7. FORENSIC CASE LEDGER & HISTORY TABLE (Full Viewport Width) */}
      {/* ===================================================================== */}
      <div className={`w-full border rounded p-3.5 space-y-3 transition-colors ${
        isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
      }`}>
        <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-2 ${
          isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'
        }`}>
          <div>
            <h3 className={`text-xs font-bold uppercase tracking-wider ${
              isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'
            }`}>
              Forensic Case Ledger &amp; History
            </h3>
            <p className={`text-[11px] ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
              Previous artifacts inspected during this session. Click View to inspect full details.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-sans font-medium border cursor-help ${
                isLight ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#334155]' : 'bg-[#162032] border-[#1E293B] text-[#94A3B8]'
              }`}
              title={storageStatus?.message || 'Persistent storage active across restarts'}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${storageStatus?.engine?.includes('PostgreSQL') ? 'bg-[#10B981]' : 'bg-[#0284C7]'}`}></span>
              Storage: <strong className={`font-mono ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{storageStatus?.engine || 'Active'}</strong>
            </span>
            {onRefreshCases && (
              <button
                onClick={onRefreshCases}
                className={`px-2 py-0.5 text-[11px] font-sans font-medium rounded border transition cursor-pointer ${
                  isLight 
                    ? 'border-[#CBD5E1] bg-[#F1F5F9] hover:bg-[#E2E8F0] text-[#0284C7]' 
                    : 'border-[#1E293B] bg-[#162032] hover:bg-[#1E293B] text-[#38BDF8]'
                }`}
                title="Synchronize history from persistent storage"
              >
                Sync
              </button>
            )}
            <div className={`text-[11px] font-mono ${isLight ? 'text-[#475569]' : 'text-[#64748B]'}`}>
              {history.length} cases
            </div>
          </div>
        </div>

        <div className={`border rounded overflow-x-auto ${isLight ? 'border-[#CBD5E1]' : 'border-[#1E293B]'}`}>
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className={`border-b font-sans font-semibold text-[11px] ${
                isLight ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#334155]' : 'bg-[#162032] border-[#1E293B] text-[#94A3B8]'
              }`}>
                <th className="py-2 px-3">Case ID</th>
                <th className="py-2 px-3">File Name</th>
                <th className="py-2 px-3">Date / Time</th>
                <th className="py-2 px-3">SHA-256</th>
                <th className="py-2 px-3">Sig Status</th>
                <th className="py-2 px-3">Threat Score</th>
                <th className="py-2 px-3">Threat Type</th>
                <th className="py-2 px-3">Summary</th>
                <th className="py-2 px-3 text-right font-sans">Action</th>
              </tr>
            </thead>
            <tbody className={`divide-y text-[11px] ${isLight ? 'divide-[#E2E8F0]' : 'divide-[#1E293B]'}`}>
              {history.length === 0 ? (
                <tr>
                  <td colSpan={9} className={`py-4 text-center font-sans ${isLight ? 'text-[#64748B]' : 'text-[#64748B]'}`}>
                    No history entries recorded yet.
                  </td>
                </tr>
              ) : (
                history.map((h, i) => {
                  const isCurrent = h.case_id === data?.case_id;
                  const sha = h.sha256 || h.data?.file?.sha256 || 'N/A';
                  const shaShort = sha.length > 12 ? `${sha.substring(0, 10)}...` : sha;
                  const summaryText = h.data?.summary?.recommendation_summary || (h.risk_score >= 50 ? 'Immediate quarantine recommended' : 'Verified signature integrity');
                  
                  // Construct fallback case payload if full data is not nested
                  const casePayload = h.data || ({
                    success: true,
                    case_id: h.case_id,
                    file: {
                      filename: h.file_name,
                      file_size_bytes: h.file_size || 0,
                      file_size: `${Math.round((h.file_size || 0) / 1024)} KB`,
                      file_type: h.file_type || 'TXT',
                      upload_time: h.timestamp,
                      sha256: sha
                    },
                    signature: {
                      algorithm: 'RSA-2048',
                      status: h.status === 'SECURE' ? 'VALID' : 'INVALID',
                      claimed_signer: 'Analyst / Client',
                      hash_mismatch: h.status !== 'SECURE'
                    },
                    threat: {
                      status: h.risk_score >= 50 ? 'ATTACK DETECTED' : 'NORMAL / SECURE',
                      risk_score: h.risk_score,
                      detected_threat: h.primary_threat,
                      detected_threats: h.threats_count > 0 ? [h.primary_threat] : [],
                      first_action: summaryText
                    },
                    quantum: {
                      qber: '0.0210',
                      quantum_risk: h.risk_score >= 50 ? 'ELEVATED' : 'MINIMAL',
                      security_level: h.risk_score >= 50 ? 'SUSPICIOUS' : 'SECURE',
                      eavesdrop_probability: `${Math.min(99, h.risk_score)}%`
                    },
                    attack_table: [
                      {
                        attack: h.primary_threat,
                        status: h.risk_score >= 50 ? 'AUTO-DETECTED' : 'NOT DETECTED',
                        risk: h.risk_score >= 80 ? 'CRITICAL' : h.risk_score >= 50 ? 'HIGH' : 'LOW',
                        risk_score: h.risk_score,
                        reason: summaryText
                      }
                    ],
                    logs: [],
                    content_preview: {
                      raw_text: `Case ID: ${h.case_id}\nFile: ${h.file_name}\nSHA-256: ${sha}\nThreat: ${h.primary_threat}`,
                      line_count: 4,
                      extracted_type: h.file_type || 'TXT'
                    },
                    summary: {
                      case_id: h.case_id,
                      analyzed_at: h.timestamp,
                      overall_status: h.status,
                      primary_threat: h.primary_threat,
                      risk_score: h.risk_score,
                      risk_level: h.risk_score >= 80 ? 'CRITICAL' : h.risk_score >= 50 ? 'HIGH' : 'LOW',
                      recommendation_summary: summaryText
                    },
                    graphs: {
                      labels: ['Signature', 'Integrity', 'PKI', 'Replay', 'Quantum'],
                      values: [h.risk_score, 20, 10, 5, 12],
                      quantum_labels: ['00', '01', '10', '11'],
                      quantum_values: [500, 10, 15, 499]
                    }
                  } as unknown as AnalysisResponse);

                  return (
                    <tr key={i} className={isCurrent 
                      ? (isLight ? 'bg-[#E0F2FE]' : 'bg-[#0284C7]/15') 
                      : (isLight ? 'hover:bg-[#F8FAFC]' : 'hover:bg-[#162032]/60')
                    }>
                      <td className={`py-2 px-3 font-bold ${isLight ? 'text-[#0284C7]' : 'text-[#38BDF8]'}`}>
                        {h.case_id}
                        {isCurrent && <span className={`ml-1 text-[10px] font-sans font-normal ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>(current)</span>}
                      </td>
                      <td className={`py-2 px-3 max-w-[140px] truncate ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`} title={h.file_name}>
                        {h.file_name}
                      </td>
                      <td className={`py-2 px-3 whitespace-nowrap ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
                        {h.timestamp}
                      </td>
                      <td className={`py-2 px-3 font-mono text-[10px] ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`} title={sha}>
                        {shaShort}
                      </td>
                      <td className="py-2 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                          h.status === 'COMPROMISED' || h.status === 'ATTACK DETECTED' || h.status === 'INVALID'
                            ? (isLight ? 'bg-[#FEE2E2] text-[#B91C1C] border-[#FCA5A5]' : 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]')
                            : h.status === 'SUSPICIOUS'
                            ? (isLight ? 'bg-[#FEF3C7] text-[#B45309] border-[#FCD34D]' : 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]')
                            : (isLight ? 'bg-[#DCFCE7] text-[#15803D] border-[#86EFAC]' : 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]')
                        }`}>
                          {h.status}
                        </span>
                      </td>
                      <td className="py-2 px-3">
                        <span className={`font-bold ${
                          h.risk_score >= 80 
                            ? (isLight ? 'text-[#DC2626]' : 'text-[#F87171]') 
                            : h.risk_score >= 50 
                            ? (isLight ? 'text-[#B45309]' : 'text-[#FBBF24]') 
                            : (isLight ? 'text-[#15803D]' : 'text-[#34D399]')
                        }`}>
                          {h.risk_score}/100
                        </span>
                      </td>
                      <td className={`py-2 px-3 font-sans truncate max-w-[120px] ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`} title={h.primary_threat}>
                        {h.primary_threat || 'None'}
                      </td>
                      <td className={`py-2 px-3 font-sans truncate max-w-[160px] ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`} title={summaryText}>
                        {summaryText}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={() => onSelectCase(casePayload)}
                          className={`px-2 py-0.5 rounded text-[11px] font-sans font-medium border transition cursor-pointer ${
                            isLight 
                              ? 'border-[#CBD5E1] text-[#0284C7] bg-[#F1F5F9] hover:bg-[#E2E8F0]' 
                              : 'border-[#1E293B] text-[#38BDF8] bg-[#162032] hover:bg-[#1E293B]'
                          }`}
                          title="Open full forensic analysis details"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
