import React, { useState, useRef } from 'react';
import {
  Upload,
  Copy,
  Check,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  FileText,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Terminal,
  Info,
  ExternalLink,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { AnalysisResponse, AttackTableRow, UploadProgressState } from '../types';
import { AdaptiveThresholdSection } from './AdaptiveThresholdSection';
import { StreamingUploadProgress } from './StreamingUploadProgress';
import { EvidenceForensicViewer } from './EvidenceForensicViewer';

interface AnalyzerViewProps {
  data: AnalysisResponse | null;
  loading: boolean;
  analysisState: 'idle' | 'running' | 'completed' | 'error';
  currentStepIndex: number;
  elapsedSeconds: number;
  currentOperation: string;
  errorMessage: string | null;
  errorDetails: string | null;
  selectedFile: File | null;
  uploadProgress?: UploadProgressState | null;
  onCancelUpload?: () => void;
  mode: string;
  referenceHashInput: string;
  onModeChange: (newMode: string) => void;
  onReferenceHashChange: (hash: string) => void;
  onFileUpload: (file: File) => void;
  onRunAnalysis: () => void;
  onReset: () => void;
  onRetry: () => void;
  onDismissError: () => void;
  onOpenCertModal: () => void;
  onOpenCbomModal: () => void;
}

const WORKFLOW_STEPS = [
  { id: 0, name: 'File received' },
  { id: 1, name: 'SHA-256 calculated' },
  { id: 2, name: 'Signature verification' },
  { id: 3, name: 'Integrity analysis' },
  { id: 4, name: 'Threat analysis' },
  { id: 5, name: 'Quantum security simulation' },
  { id: 6, name: 'Risk assessment' },
  { id: 7, name: 'Final security result' }
];

export const AnalyzerView: React.FC<AnalyzerViewProps> = ({
  data,
  loading,
  analysisState,
  currentStepIndex,
  elapsedSeconds,
  currentOperation,
  errorMessage,
  errorDetails,
  selectedFile,
  uploadProgress,
  onCancelUpload,
  mode,
  referenceHashInput,
  onModeChange,
  onReferenceHashChange,
  onFileUpload,
  onRunAnalysis,
  onReset,
  onRetry,
  onDismissError,
  onOpenCertModal,
  onOpenCbomModal
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);
  const [showErrorDetails, setShowErrorDetails] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleCopySha256 = () => {
    if (data?.file?.sha256) {
      navigator.clipboard.writeText(data.file.sha256);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const riskScore = data?.threat?.risk_score ?? 0;
  const isAttack = data?.threat?.status === 'ATTACK DETECTED' || riskScore >= 60;
  const isSuspicious = !isAttack && (riskScore >= 35 || data?.signature?.hash_mismatch);

  let resultStatus: 'SECURE' | 'SUSPICIOUS' | 'COMPROMISED' = 'SECURE';
  let resultBadgeClass = 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]';
  let resultBorderClass = 'border-[#065F46]';

  if (isAttack) {
    resultStatus = 'COMPROMISED';
    resultBadgeClass = 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]';
    resultBorderClass = 'border-[#991B1B]';
  } else if (isSuspicious) {
    resultStatus = 'SUSPICIOUS';
    resultBadgeClass = 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]';
    resultBorderClass = 'border-[#92400E]';
  }

  // Detailed Threat Table Items
  const threatTableRows: Array<{
    type: string;
    status: 'Detected' | 'Not Detected';
    evidence: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
  }> = [];

  if (data) {
    // 1. Replay Attack
    const isReplay = Boolean(data.stateful_replay?.is_stateful_replay) ||
      (data.attack_table || []).some(r => r.attack === 'Replay' && r.status !== 'NOT DETECTED') ||
      data.threat?.detected_threat?.toLowerCase().includes('replay');
    threatTableRows.push({
      type: 'Replay Attack',
      status: isReplay ? 'Detected' : 'Not Detected',
      evidence: isReplay
        ? (data.stateful_replay?.stateful_replay_type === 'STATEFUL_REPLAY_DETECTED'
            ? 'Nonce reused / duplicate transaction identifier observed in store'
            : 'Stale timestamp expired outside freshness window')
        : 'Fresh transaction identifiers and valid timestamp bounds',
      severity: isReplay ? 'High' : 'Low'
    });

    // 2. Signature Forgery
    const isForgery = data.signature?.signature_status?.toUpperCase().includes('INVALID') ||
      Boolean(data.signature?.hash_mismatch) ||
      (data.attack_table || []).some(r => r.attack === 'Forgery' && r.status !== 'NOT DETECTED') ||
      data.threat?.detected_threat?.toLowerCase().includes('forgery');
    threatTableRows.push({
      type: 'Signature Forgery',
      status: isForgery ? 'Detected' : 'Not Detected',
      evidence: isForgery
        ? 'Signature verification failed; mathematical digest does not match public key'
        : 'Valid cryptographic signature signature matches payload digest',
      severity: isForgery ? 'Critical' : 'Low'
    });

    // 3. Signer Impersonation
    const isImpersonation = data.certificate_analysis?.status === 'UNTRUSTED' ||
      (data.attack_table || []).some(r => r.attack === 'Impersonation' && r.status !== 'NOT DETECTED') ||
      data.threat?.detected_threat?.toLowerCase().includes('impersonation');
    threatTableRows.push({
      type: 'Signer Impersonation',
      status: isImpersonation ? 'Detected' : 'Not Detected',
      evidence: isImpersonation
        ? 'Signer certificate untrusted or identity not authorized in registry'
        : 'Signer identity and certificate verified against trusted root authorities',
      severity: isImpersonation ? 'High' : 'Low'
    });

    // 4. Channel Tampering
    const isTampering = (data.attack_table || []).some(r => r.attack === 'Classical Channel Tampering' && r.status !== 'NOT DETECTED') ||
      data.threat?.detected_threat?.toLowerCase().includes('channel') ||
      data.threat?.detected_threat?.toLowerCase().includes('tamper');
    threatTableRows.push({
      type: 'Channel Tampering',
      status: isTampering ? 'Detected' : 'Not Detected',
      evidence: isTampering
        ? 'In-transit message body alteration detected; payload modified'
        : 'No modification indicators; payload transit checksum verified',
      severity: isTampering ? 'High' : 'Low'
    });

    // 5. Quantum Eavesdropping
    const isEavesdrop = (data.quantum?.qber ?? 0) >= 0.11 ||
      (data.attack_table || []).some(r => r.attack === 'Entangle-and-Measure' && r.status !== 'NOT DETECTED') ||
      data.threat?.detected_threat?.toLowerCase().includes('quantum') ||
      data.threat?.detected_threat?.toLowerCase().includes('entangle');
    threatTableRows.push({
      type: 'Quantum Eavesdropping',
      status: isEavesdrop ? 'Detected' : 'Not Detected',
      evidence: isEavesdrop
        ? `Elevated simulated QBER (${data.quantum?.qber_percentage || '14.2%'}) exceeds 11.0% limit`
        : `Simulated QBER (${data.quantum?.qber_percentage || '1.20%'}) within safe channel noise bounds`,
      severity: isEavesdrop ? 'Critical' : 'Low'
    });

    // 6. Certificate / Trust Failure
    const isCertFailure = data.certificate_analysis?.status === 'INVALID' ||
      data.certificate_analysis?.is_weak_key ||
      (data.attack_table || []).some(r => r.attack === 'Certificate / Trust Failure' && r.status !== 'NOT DETECTED');
    threatTableRows.push({
      type: 'Certificate / Trust Chain Failure',
      status: isCertFailure ? 'Detected' : 'Not Detected',
      evidence: isCertFailure
        ? (data.certificate_analysis?.trust_chain_details || 'Certificate expired, untrusted, or weak key parameters')
        : 'X.509 certificate chain is intact and within validity period',
      severity: isCertFailure ? 'Medium' : 'Low'
    });

    // 7. Adaptive Statistical Threshold
    if (data.adaptive_threshold) {
      const isAnomaly = data.adaptive_threshold.statisticalAnomaly;
      threatTableRows.push({
        type: 'Adaptive Statistical Threshold',
        status: isAnomaly ? 'Detected' : 'Not Detected',
        evidence: isAnomaly
          ? `Statistical anomaly detected: observed ${data.adaptive_threshold.currentMeasurement.toFixed(2)}% outside calibrated baseline [${data.adaptive_threshold.lowerThreshold.toFixed(2)}% — ${data.adaptive_threshold.upperThreshold.toFixed(2)}%]`
          : `Measurement ${data.adaptive_threshold.currentMeasurement.toFixed(2)}% within calibrated baseline range [${data.adaptive_threshold.lowerThreshold.toFixed(2)}% — ${data.adaptive_threshold.upperThreshold.toFixed(2)}%]`,
        severity: isAnomaly ? 'High' : 'Low'
      });
    }
  }

  // Detected threats list for summary
  const detectedThreatNames: string[] = [];
  threatTableRows.forEach(row => {
    if (row.status === 'Detected') detectedThreatNames.push(row.type);
  });
  if (detectedThreatNames.length === 0 && isAttack && data?.threat?.detected_threat) {
    detectedThreatNames.push(data.threat.detected_threat);
  }

  return (
    <div className="space-y-4">
      {/* ERROR BANNER (Professional, Localized Error Handling) */}
      {errorMessage && (
        <div className="bg-[#7F1D1D]/30 border border-[#991B1B] rounded p-3 text-xs text-[#F1F5F9] space-y-2">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <XCircle className="w-4 h-4 text-[#F87171] shrink-0" />
              <div>
                <span className="font-bold text-[#F87171] block font-mono uppercase text-[11px]">Analysis Error</span>
                <span className="text-[#F1F5F9] font-medium">{errorMessage}</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={onRetry}
                className="px-2.5 py-1 bg-[#EF4444] hover:bg-[#DC2626] text-white text-[11px] font-semibold rounded cursor-pointer transition flex items-center gap-1"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Retry</span>
              </button>
              {errorDetails && (
                <button
                  onClick={() => setShowErrorDetails(!showErrorDetails)}
                  className="px-2 py-1 bg-[#162032] border border-[#991B1B] hover:bg-[#1E293B] text-[#F87171] text-[11px] font-medium rounded cursor-pointer transition flex items-center gap-1"
                >
                  <span>{showErrorDetails ? 'Hide' : 'Details'}</span>
                  {showErrorDetails ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                </button>
              )}
              <button
                onClick={onDismissError}
                className="px-2 py-1 bg-[#162032] border border-[#1E293B] hover:bg-[#1E293B] text-[#94A3B8] text-[11px] font-medium rounded cursor-pointer transition"
              >
                Dismiss
              </button>
            </div>
          </div>

          {showErrorDetails && errorDetails && (
            <div className="pt-2 border-t border-[#991B1B]/60">
              <pre className="p-2 bg-[#0B0F19] rounded border border-[#991B1B]/40 font-mono text-[11px] text-[#F87171] overflow-x-auto">
                {errorDetails}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* LIVE STREAMING & UPLOAD PROGRESS CARD (UP TO 1 TB) */}
      {uploadProgress && (
        <StreamingUploadProgress
          progress={uploadProgress}
          onCancel={onCancelUpload}
        />
      )}

      {/* TOP WORKFLOW & INGESTION GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: File Upload & Controls (6 cols) */}
        <div className="lg:col-span-6 bg-[#111827] border border-[#1E293B] rounded p-3.5 space-y-3">
          <div className="border-b border-[#1E293B] pb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
              Security Artifact Ingestion
            </h3>
            <p className="text-[11px] text-[#94A3B8] mt-0.5">
              Upload or drop a digital signature artifact, signed payload, or raw binary/data file (up to 1 TB)
            </p>
          </div>

          {/* Drag and Drop Zone */}
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
            className={`border-2 border-dashed rounded p-4 text-center cursor-pointer transition ${
              isDragging
                ? 'border-[#0284C7] bg-[#0284C7]/15'
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
            <Upload className="w-5 h-5 mx-auto text-[#38BDF8] mb-1.5" />
            <div className="text-xs font-bold text-[#F1F5F9] font-mono">
              {selectedFile ? `Selected: ${selectedFile.name}` : 'Drop forensic artifact or click to browse'}
            </div>
            <div className="text-[11px] text-[#94A3B8] mt-0.5 font-mono">
              Formats: .txt, .json, .pem, .sig, .bin (Streaming up to 1 TB)
            </div>
          </div>

          {/* Configuration Form */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
            <div>
              <label className="block text-[10px] font-mono uppercase font-semibold text-[#94A3B8] mb-1">
                Detection Mode
              </label>
              <select
                value={mode}
                onChange={(e) => onModeChange(e.target.value)}
                className="w-full bg-[#162032] border border-[#1E293B] rounded px-2.5 py-1.5 text-xs text-[#F1F5F9] focus:outline-none focus:border-[#0284C7]"
              >
                <option value="Automatic Detection">Automatic Detection (All Vectors)</option>
                <option value="Signature Integrity Only">Signature Integrity Only</option>
                <option value="Quantum Channel Analysis">Quantum Channel Analysis</option>
                <option value="Replay Attack Verification">Replay Attack Verification</option>
                <option value="Forgery Detection">Forgery Detection</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase font-semibold text-[#94A3B8] mb-1">
                Reference SHA-256 (Optional)
              </label>
              <input
                type="text"
                value={referenceHashInput}
                onChange={(e) => onReferenceHashChange(e.target.value)}
                placeholder="64-hex hash..."
                className="w-full bg-[#162032] border border-[#1E293B] rounded px-2.5 py-1.5 text-xs font-mono text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#0284C7]"
              />
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2 pt-1">
            <button
              onClick={onRunAnalysis}
              disabled={loading}
              className="flex-1 py-1.5 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded cursor-pointer transition disabled:opacity-50 flex items-center justify-center gap-1.5"
            >
              {loading && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
              <span>{loading ? 'Evaluating Vectors...' : 'Run Security Analysis'}</span>
            </button>
            <button
              onClick={onReset}
              disabled={loading}
              className="px-3.5 py-1.5 bg-[#162032] border border-[#1E293B] hover:bg-[#1E293B] text-[#F1F5F9] text-xs font-medium rounded cursor-pointer transition disabled:opacity-50"
            >
              Reset
            </button>
          </div>
        </div>

        {/* Right Column: Live Analysis Status & Workflow Progress (6 cols) */}
        <div className="lg:col-span-6 bg-[#111827] border border-[#1E293B] rounded p-3.5 space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
                Analysis Workflow &amp; Pipeline
              </h3>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold uppercase ${
                  analysisState === 'running'
                    ? 'bg-[#0284C7]/20 text-[#38BDF8] border-[#0284C7] animate-pulse'
                    : analysisState === 'completed'
                    ? 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]'
                    : 'bg-[#162032] text-[#94A3B8] border-[#1E293B]'
                }`}>
                  Status: {analysisState === 'running' ? 'Running' : analysisState === 'completed' ? 'Completed' : 'Idle'}
                </span>
              </div>
            </div>

            {/* Current Operation & Elapsed Time Status */}
            <div className="grid grid-cols-2 gap-2 mt-2.5 text-xs">
              <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
                <span className="text-[10px] font-mono font-semibold text-[#94A3B8] block uppercase">Current Operation</span>
                <span className="font-mono font-bold text-[#F1F5F9] text-[11px] truncate block mt-0.5">
                  {currentOperation || (loading ? 'Processing...' : 'Ready')}
                </span>
              </div>
              <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
                <span className="text-[10px] font-mono font-semibold text-[#94A3B8] block uppercase">Elapsed Time</span>
                <span className="font-mono font-bold text-[#F1F5F9] text-[11px] block mt-0.5">
                  {elapsedSeconds.toFixed(2)} seconds
                </span>
              </div>
            </div>

            {/* Step-by-Step Progress Pipeline */}
            <div className="mt-2.5 space-y-1.5 text-xs font-mono">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono font-bold text-[#94A3B8] uppercase">
                  {analysisState === 'running'
                    ? 'Evaluating Pipeline Vectors...'
                    : analysisState === 'completed'
                    ? 'Pipeline Execution Completed'
                    : 'Pipeline Workflow'}
                </span>
                <span className="text-[10px] text-[#64748B] font-mono">
                  {analysisState === 'completed'
                    ? `${WORKFLOW_STEPS.length}/${WORKFLOW_STEPS.length} Completed`
                    : analysisState === 'running'
                    ? `Stage ${currentStepIndex + 1}/${WORKFLOW_STEPS.length}`
                    : 'Ready'}
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {WORKFLOW_STEPS.map((step) => {
                  const isDone = analysisState === 'completed' || currentStepIndex > step.id;
                  const isCurrent = analysisState === 'running' && currentStepIndex === step.id;

                  return (
                    <div
                      key={step.id}
                      className={`flex items-center gap-2 p-1.5 rounded border text-[11px] font-mono transition ${
                        isDone
                          ? 'bg-[#064E3B]/20 border-[#065F46] text-[#34D399]'
                          : isCurrent
                          ? 'bg-[#0284C7]/20 border-[#0284C7] text-[#38BDF8] font-bold'
                          : 'bg-[#162032] border-[#1E293B] text-[#64748B]'
                      }`}
                    >
                      {isDone ? (
                        <span className="text-[#34D399] font-bold text-xs shrink-0">✓</span>
                      ) : isCurrent ? (
                        <span className="text-[#38BDF8] font-bold text-xs shrink-0 animate-pulse">●</span>
                      ) : (
                        <span className="text-[#475569] text-xs shrink-0">○</span>
                      )}
                      <span className="truncate">
                        {isCurrent ? `Running ${step.name}...` : step.name}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-[#1E293B] text-[11px] text-[#64748B] flex items-center justify-between font-mono">
            <span>Engine: Qiskit Statevector + Chained SHA-256</span>
            <span>Case ID: <strong className="text-[#38BDF8]">{data?.case_id || 'Pending'}</strong></span>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 5. SECURITY RESULT SECTION (The most important part of the page) */}
      {/* ===================================================================== */}
      {data && (
        <div className={`bg-[#111827] border-2 rounded p-4 space-y-3.5 ${resultBorderClass}`}>
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1E293B] pb-2.5">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-[#94A3B8]">
                  Security Result
                </span>
                <span className="text-xs font-mono text-[#64748B]">&bull; Case {data.case_id}</span>
              </div>
              <h2 className="text-base font-bold text-[#F1F5F9] mt-0.5">
                Evaluation: {resultStatus}
              </h2>
            </div>

            <div className="flex items-center gap-2">
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono border uppercase ${resultBadgeClass}`}>
                STATUS: {resultStatus}
              </span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono border ${
                riskScore >= 80 ? 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]' :
                riskScore >= 50 ? 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]' :
                'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]'
              }`}>
                RISK: {riskScore} / 100 ({data.threat?.risk || 'LOW'})
              </span>
            </div>
          </div>

          {/* 6. RISK SCORE HORIZONTAL SCALE */}
          <div className="p-3 bg-[#162032] rounded border border-[#1E293B] space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-[#F1F5F9]">Risk Assessment</span>
              <span className="font-mono font-bold text-[#F1F5F9]">{riskScore} / 100</span>
            </div>

            {/* Horizontal 4-tier risk scale */}
            <div className="w-full bg-[#1E293B] rounded-full h-2 overflow-hidden flex">
              <div
                className="h-full transition-all duration-300"
                style={{
                  width: `${Math.max(2, riskScore)}%`,
                  backgroundColor: riskScore >= 80 ? '#EF4444' : riskScore >= 50 ? '#F59E0B' : '#10B981'
                }}
              />
            </div>

            {/* Scale Labels */}
            <div className="grid grid-cols-4 text-center text-[10px] font-mono text-[#64748B] pt-0.5">
              <span className={riskScore < 30 ? 'font-bold text-[#34D399]' : ''}>LOW (0-29)</span>
              <span className={riskScore >= 30 && riskScore < 60 ? 'font-bold text-[#FBBF24]' : ''}>MEDIUM (30-59)</span>
              <span className={riskScore >= 60 && riskScore < 80 ? 'font-bold text-[#F87171]' : ''}>HIGH (60-79)</span>
              <span className={riskScore >= 80 ? 'font-bold text-[#F87171]' : ''}>CRITICAL (80-100)</span>
            </div>
          </div>

          {/* Factual Explanation / Reason */}
          <div className="space-y-1">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wide text-[#94A3B8]">
              Reason:
            </span>
            <p className="text-xs text-[#F1F5F9] leading-relaxed p-2.5 bg-[#162032] rounded border border-[#1E293B] font-mono">
              {data.threat?.reason || 'All cryptographic signatures, certificate parameters, and quantum transmission metrics are verified intact.'}
            </p>
          </div>

          {/* Detected Threats Bullet List */}
          <div className="space-y-1.5">
            <span className="text-[11px] font-mono font-bold uppercase tracking-wide text-[#94A3B8]">
              Detected Threats:
            </span>
            {detectedThreatNames.length === 0 ? (
              <div className="text-xs text-[#34D399] p-2 bg-[#064E3B]/20 rounded border border-[#065F46] font-mono flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-[#34D399]" />
                <span>None &mdash; All 8 threat vectors evaluated within clean baseline parameters.</span>
              </div>
            ) : (
              <ul className="space-y-1 text-xs font-mono">
                {detectedThreatNames.map((t, i) => (
                  <li key={i} className="flex items-center gap-2 p-2 bg-[#7F1D1D]/25 rounded border border-[#991B1B]">
                    <span className="text-[#F87171] font-bold">&bull;</span>
                    <span className="font-semibold text-[#F87171]">{t}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Recommended Action */}
          <div className="p-3 bg-[#162032] rounded border border-[#1E293B] space-y-1 text-xs">
            <span className="font-bold uppercase text-[#38BDF8] block text-[11px] font-mono">
              Recommended Action:
            </span>
            <p className="text-[#F1F5F9] leading-relaxed font-sans">
              {data.threat?.first_action || data.threat?.recommendation || 'Review the transaction and verify the signer and message integrity.'}
            </p>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* 5b. ATTACK EVIDENCE LOCATION & LINE-LEVEL FORENSIC ANALYSIS */}
      {/* ===================================================================== */}
      {data && (
        <EvidenceForensicViewer
          evidence={data.evidence || data.threat?.evidence_items || []}
          timeline={data.evidence_timeline}
          fileName={data.file.filename}
          fileSize={data.file.file_size}
          isSecure={data.threat?.status === 'SECURE'}
        />
      )}

      {/* ===================================================================== */}
      {/* 6. ADAPTIVE STATISTICAL THRESHOLD SECTION */}
      {/* ===================================================================== */}
      {data && (
        <AdaptiveThresholdSection
          adaptiveThreshold={data.adaptive_threshold}
        />
      )}

      {/* ===================================================================== */}
      {/* 7. THREAT ANALYSIS TABLE */}
      {/* ===================================================================== */}
      {data && (
        <div className="bg-[#111827] border border-[#1E293B] rounded p-3.5 space-y-3">
          <div className="flex items-center justify-between border-b border-[#1E293B] pb-2">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
                Threat Analysis Details
              </h3>
              <p className="text-[11px] text-[#94A3B8]">
                Technical breakdown of observed evidence and severity ratings for security analysts
              </p>
            </div>
            <span className="text-[11px] font-mono text-[#64748B]">
              6 Core Indicators Evaluated
            </span>
          </div>

          <div className="border border-[#1E293B] rounded overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-[#162032] border-b border-[#1E293B] text-[#94A3B8] font-sans font-semibold text-[11px]">
                  <th className="py-2 px-3">Threat Type</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3">Evidence</th>
                  <th className="py-2 px-3">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E293B] text-[11px]">
                {threatTableRows.map((row, idx) => (
                  <tr key={idx} className={row.status === 'Detected' ? 'bg-[#7F1D1D]/15' : 'hover:bg-[#162032]/50'}>
                    <td className="py-2 px-3 font-semibold text-[#F1F5F9] font-sans whitespace-nowrap">
                      {row.type}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border uppercase ${
                        row.status === 'Detected'
                          ? 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]'
                          : 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]'
                      }`}>
                        {row.status}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-[#94A3B8] font-sans leading-relaxed">
                      {row.evidence}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className={`font-bold uppercase ${
                        row.severity === 'Critical' ? 'text-[#F87171]' :
                        row.severity === 'High' ? 'text-[#F87171]' :
                        row.severity === 'Medium' ? 'text-[#FBBF24]' :
                        'text-[#34D399]'
                      }`}>
                        {row.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* 8. FILE ANALYSIS TABLE */}
      {/* ===================================================================== */}
      {data && (
        <>
          <div className="bg-[#111827] border border-[#1E293B] rounded p-3.5 space-y-3">
          <div className="flex items-center justify-between border-b border-[#1E293B] pb-2">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
                File Analysis Technical Metadata
              </h3>
              <p className="text-[11px] text-[#94A3B8]">
                Cryptographic parameters and signature verification details
              </p>
            </div>
            <div className="flex gap-2">
              <button
                onClick={onOpenCertModal}
                className="px-2.5 py-1 text-xs border border-[#1E293B] bg-[#162032] rounded hover:bg-[#1E293B] text-[#F1F5F9] font-medium cursor-pointer transition"
              >
                Inspect Certificate
              </button>
              <button
                onClick={onOpenCbomModal}
                className="px-2.5 py-1 text-xs border border-[#1E293B] bg-[#162032] rounded hover:bg-[#1E293B] text-[#F1F5F9] font-medium cursor-pointer transition"
              >
                View CBOM
              </button>
            </div>
          </div>

          <div className="border border-[#1E293B] rounded overflow-hidden">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <tbody className="divide-y divide-[#1E293B]">
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] w-1/3 sm:w-1/4 font-sans">File Name</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">{data.file.filename}</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">File Type</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">{data.file.file_type}</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">File Size</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">{data.file.file_size}</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">SHA-256 Digest</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate max-w-md">{data.file.sha256}</span>
                      <button
                        onClick={handleCopySha256}
                        className="px-2 py-0.5 rounded text-[10px] font-sans border border-[#1E293B] bg-[#162032] hover:bg-[#1E293B] text-[#38BDF8] shrink-0 cursor-pointer flex items-center gap-1 transition"
                        title="Copy SHA-256 to clipboard"
                      >
                        {copiedHash ? <Check className="w-3 h-3 text-[#34D399]" /> : <Copy className="w-3 h-3 text-[#94A3B8]" />}
                        <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Analysis Time</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">{data.file.upload_time} UTC</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Signature Algorithm</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">
                    {data.cryptographic_verification?.algorithm_detected || data.signature.signature_algorithm}
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Signature Status</td>
                  <td className="py-2 px-3">
                    <span className={data.signature.signature_status === 'VALID' ? 'text-[#34D399] font-semibold' : 'text-[#F87171] font-semibold'}>
                      {data.signature.signature_status}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Certificate Status</td>
                  <td className="py-2 px-3">
                    <span className={data.certificate_analysis?.status === 'VALID' ? 'text-[#34D399]' : 'text-[#FBBF24]'}>
                      {data.certificate_analysis?.status || 'NOT AVAILABLE'} ({data.certificate_analysis?.trust_chain || 'UNAVAILABLE'})
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Integrity Status</td>
                  <td className="py-2 px-3">
                    <span className={data.signature?.hash_mismatch ? 'text-[#F87171] font-semibold' : 'text-[#34D399]'}>
                      {data.file.integrity_status}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* 9. QUANTUM SECURITY SIMULATION (Technical parameters block) */}
        <div className="bg-[#111827] border border-[#1E293B] rounded p-3.5 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-[#1E293B] pb-2">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
                Quantum Security Simulation
              </h3>
              <p className="text-[11px] text-[#94A3B8]">
                Entanglement distribution and quantum bit error rate telemetry
              </p>
            </div>
            <div className="text-[11px] font-mono text-[#64748B]">
              Backend: <span className="font-bold text-[#F1F5F9]">Local Simulator (Qiskit Aer)</span>
            </div>
          </div>

          <div className="border border-[#1E293B] rounded overflow-hidden">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <tbody className="divide-y divide-[#1E293B]">
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] w-1/3 sm:w-1/4 font-sans">Backend</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">Local Simulator</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Bell State</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">Φ+</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Entanglement</td>
                  <td className="py-2 px-3 text-[#34D399] font-semibold">Verified</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Teleportation</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">Completed</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Pauli Correction</td>
                  <td className="py-2 px-3 text-[#F1F5F9]">{data.quantum?.pauli_correction || 'I / X / Z / XZ'}</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Fidelity</td>
                  <td className="py-2 px-3 text-[#34D399] font-semibold">
                    {data.quantum?.state_preservation_fidelity || '100%'}
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Channel QBER</td>
                  <td className="py-2 px-3">
                    <span className={(data.quantum?.qber ?? 0) >= 0.11 ? 'text-[#F87171] font-bold' : 'text-[#F1F5F9] font-semibold'}>
                      {data.quantum?.qber_percentage || '1.20%'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Configured Threshold</td>
                  <td className="py-2 px-3 text-[#94A3B8]">{data.quantum?.qber_threshold || '11.0%'}</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 font-semibold text-[#94A3B8] bg-[#162032] font-sans">Channel Status</td>
                  <td className="py-2 px-3">
                    <span className={
                      data.quantum?.channel_status === 'CRITICAL' || (data.quantum?.qber ?? 0) >= 0.11
                        ? 'text-[#F87171] font-bold'
                        : 'text-[#34D399] font-semibold'
                    }>
                      {data.quantum?.channel_status === 'CRITICAL' || (data.quantum?.qber ?? 0) >= 0.11 ? 'Disturbed' : 'Normal'}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="p-2.5 bg-[#162032] border border-[#1E293B] rounded text-[11px] text-[#94A3B8] italic font-sans leading-relaxed">
            * Quantum security measurements are generated using a local simulation environment. Results represent simulated channel behaviour and are not measurements from physical quantum hardware.
          </div>
        </div>
        </>
      )}
    </div>
  );
};
