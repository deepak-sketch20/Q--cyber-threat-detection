import React from 'react';
import { UploadProgressState } from '../types';
import { CheckCircle2, AlertTriangle, XCircle, RefreshCw, HardDrive, Hash, ShieldCheck, ShieldAlert } from 'lucide-react';

interface StreamingUploadProgressProps {
  progress: UploadProgressState;
  onCancel?: () => void;
}

export const StreamingUploadProgress: React.FC<StreamingUploadProgressProps> = ({
  progress,
  onCancel
}) => {
  if (progress.uploadStatus === 'idle' && progress.analysisStatus === 'idle') {
    return null;
  }

  const isUploading = progress.uploadStatus === 'uploading';
  const isUploadComplete = progress.uploadStatus === 'completed';
  const isAnalysisRunning = progress.analysisStatus === 'running';
  const isAnalysisComplete = progress.analysisStatus === 'completed';
  const isError = progress.uploadStatus === 'error' || progress.analysisStatus === 'error';

  return (
    <div className="bg-[#111827] border-2 border-[#0284C7] rounded p-3.5 shadow-sm mb-4 space-y-3 transition-all duration-200">
      {/* Header bar */}
      <div className="flex items-center justify-between border-b border-[#1E293B] pb-2.5">
        <div className="flex items-center gap-2">
          <div className={`p-1.5 rounded ${
            isError ? 'bg-[#7F1D1D]/40 text-[#F87171]' :
            isAnalysisComplete ? 'bg-[#064E3B]/40 text-[#34D399]' :
            'bg-[#0284C7]/20 text-[#38BDF8]'
          }`}>
            {isError ? <XCircle className="w-4 h-4" /> :
             isAnalysisComplete ? <ShieldCheck className="w-4 h-4" /> :
             <HardDrive className="w-4 h-4 animate-pulse" />}
          </div>
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
              Security Analysis &amp; Streaming Ingestion
            </h4>
            <p className="text-[11px] text-[#94A3B8]">
              High-Capacity 1 TB Chunked Streaming Pipeline with Incremental SHA-256
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {isUploading && onCancel && (
            <button
              onClick={onCancel}
              className="px-2 py-0.5 text-[11px] text-[#F87171] hover:bg-[#7F1D1D]/30 border border-[#991B1B] rounded transition"
            >
              Cancel Upload
            </button>
          )}
          <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
            isError ? 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]' :
            isAnalysisComplete ? (
              progress.finalVerdict === 'COMPROMISED' ? 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]' :
              progress.finalVerdict === 'SUSPICIOUS' ? 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]' :
              'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]'
            ) :
            'bg-[#0284C7]/20 text-[#38BDF8] border-[#0284C7] animate-pulse'
          }`}>
            {isError ? 'Error' :
             isAnalysisComplete ? (progress.finalVerdict || 'Completed') :
             isUploading ? `Uploading ${progress.uploadPercent}%` :
             'Running Analysis'}
          </span>
        </div>
      </div>

      {/* Grid of File & Telemetry details */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 text-xs">
        {/* File Name */}
        <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
          <span className="text-[10px] font-semibold text-[#94A3B8] uppercase block">File</span>
          <span className="font-mono font-bold text-[#F1F5F9] text-[11px] truncate block mt-0.5" title={progress.fileName}>
            {progress.fileName || 'Pending selection'}
          </span>
        </div>

        {/* File Size */}
        <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
          <span className="text-[10px] font-semibold text-[#94A3B8] uppercase block">Size</span>
          <span className="font-mono font-bold text-[#F1F5F9] text-[11px] block mt-0.5">
            {progress.fileSizeFormatted || '0 bytes'}
          </span>
        </div>

        {/* Upload Status */}
        <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
          <span className="text-[10px] font-semibold text-[#94A3B8] uppercase block">Upload</span>
          <span className="font-mono font-bold text-[11px] block mt-0.5 text-[#F1F5F9] flex items-center gap-1">
            {isUploadComplete ? (
              <><CheckCircle2 className="w-3.5 h-3.5 text-[#34D399]" /> Completed</>
            ) : isUploading ? (
              <><RefreshCw className="w-3.5 h-3.5 text-[#38BDF8] animate-spin" /> {progress.uploadPercent}%</>
            ) : isError ? (
              <><XCircle className="w-3.5 h-3.5 text-[#F87171]" /> Failed</>
            ) : (
              'Waiting...'
            )}
          </span>
        </div>

        {/* SHA-256 Status */}
        <div className="p-2 bg-[#162032] rounded border border-[#1E293B]">
          <span className="text-[10px] font-semibold text-[#94A3B8] uppercase block flex items-center justify-between">
            <span>SHA-256</span>
            <span className="text-[9px] text-[#64748B] lowercase">incremental</span>
          </span>
          <span className="font-mono font-bold text-[11px] block mt-0.5 text-[#F1F5F9] flex items-center gap-1">
            {progress.sha256Status === 'completed' ? (
              <><CheckCircle2 className="w-3.5 h-3.5 text-[#34D399]" /> Completed</>
            ) : progress.sha256Status === 'calculating' ? (
              <><RefreshCw className="w-3.5 h-3.5 text-[#38BDF8] animate-spin" /> Calculating...</>
            ) : isError ? (
              <><XCircle className="w-3.5 h-3.5 text-[#F87171]" /> Failed</>
            ) : (
              'Pending...'
            )}
          </span>
        </div>
      </div>

      {/* Progress Bar & Byte Count */}
      <div className="space-y-1">
        <div className="flex items-center justify-between text-[11px]">
          <span className="font-medium text-[#F1F5F9]">
            {isUploading
              ? `Uploading... ${progress.uploadPercent}%`
              : isUploadComplete && isAnalysisRunning
              ? 'Upload completed. Starting security analysis...'
              : isAnalysisComplete
              ? 'Security Analysis Completed'
              : isError
              ? 'Operation Terminated'
              : 'Standby'}
          </span>
          <span className="font-mono text-[#94A3B8]">
            {isUploading && progress.totalBytes > 0
              ? `Uploaded: ${(progress.uploadedBytes / (1024 * 1024)).toFixed(1)} MB / ${(progress.totalBytes / (1024 * 1024)).toFixed(1)} MB`
              : progress.fileSizeFormatted}
          </span>
        </div>

        {/* Bar */}
        <div className="w-full bg-[#1E293B] rounded-full h-2 overflow-hidden">
          <div
            className={`h-full transition-all duration-150 rounded-full ${
              isError ? 'bg-[#EF4444]' :
              isAnalysisComplete ? 'bg-[#10B981]' :
              'bg-[#0284C7]'
            }`}
            style={{ width: `${Math.max(3, progress.uploadPercent)}%` }}
          />
        </div>
      </div>

      {/* SHA-256 Calculated Hex Hash Display when available */}
      {progress.calculatedHash && (
        <div className="p-2 bg-[#162032] rounded border border-[#1E293B] font-mono text-[11px] text-[#F1F5F9] flex items-center gap-2">
          <Hash className="w-3.5 h-3.5 text-[#38BDF8] shrink-0" />
          <span className="text-[#94A3B8] shrink-0">SHA-256:</span>
          <span className="truncate select-all">{progress.calculatedHash}</span>
        </div>
      )}

      {/* Analysis Status & Verdict */}
      <div className="pt-2 border-t border-[#1E293B] flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-[#94A3B8] font-semibold">Security Analysis:</span>
          <span className="font-mono font-medium text-[#F1F5F9]">
            {progress.analysisStatus === 'running' ? (
              <span className="text-[#38BDF8] flex items-center gap-1 font-bold">
                <RefreshCw className="w-3 h-3 animate-spin" /> Running...
              </span>
            ) : progress.analysisStatus === 'completed' ? (
              <span className="text-[#34D399] font-bold">Completed</span>
            ) : progress.analysisStatus === 'waiting' ? (
              <span className="text-[#94A3B8]">Waiting for upload...</span>
            ) : (
              'Standby'
            )}
          </span>
        </div>

        {isAnalysisComplete && progress.finalVerdict && (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1">
              <span className="text-[#94A3B8] font-semibold">Final:</span>
              <span className={`font-mono font-bold px-2 py-0.5 rounded text-[11px] border uppercase ${
                progress.finalVerdict === 'COMPROMISED' ? 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]' :
                progress.finalVerdict === 'SUSPICIOUS' ? 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]' :
                'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]'
              }`}>
                {progress.finalVerdict}
              </span>
            </div>
            {typeof progress.riskScore === 'number' && (
              <div className="flex items-center gap-1">
                <span className="text-[#94A3B8] font-semibold">Risk:</span>
                <span className="font-mono font-bold text-[11px] text-[#F1F5F9]">
                  {progress.riskScore} / 100
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Error Banner */}
      {isError && progress.error && (
        <div className="p-2.5 bg-[#7F1D1D]/30 border border-[#991B1B] rounded text-xs text-[#F87171] flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold block">Upload / Validation Error</span>
            <span>{progress.error}</span>
          </div>
        </div>
      )}
    </div>
  );
};
