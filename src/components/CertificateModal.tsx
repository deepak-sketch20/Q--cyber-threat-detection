import React from 'react';
import { ShieldCheck, AlertTriangle, X, CheckCircle, Lock, Link } from 'lucide-react';
import { CertificateAnalysisInfo } from '../types';

interface CertificateModalProps {
  cert?: CertificateAnalysisInfo;
  isOpen: boolean;
  onClose: () => void;
  isDark: boolean;
}

export const CertificateModal: React.FC<CertificateModalProps> = ({ cert, isOpen, onClose, isDark }) => {
  if (!isOpen || !cert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className={`w-full max-w-2xl rounded-xl border shadow-2xl flex flex-col max-h-[90vh] overflow-hidden ${
        isDark ? 'bg-[#0f172a] border-slate-700 text-slate-100' : 'bg-white border-slate-200 text-slate-900'
      }`}>
        {/* Header */}
        <div className={`flex items-center justify-between px-5 py-4 border-b ${
          isDark ? 'border-slate-800 bg-slate-900/80' : 'border-slate-200 bg-slate-50'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              cert.status === 'VALID'
                ? isDark ? 'bg-emerald-500/20 text-emerald-300' : 'bg-emerald-50 text-emerald-700'
                : isDark ? 'bg-rose-500/20 text-rose-300' : 'bg-rose-50 text-rose-700'
            }`}>
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold">X.509 PKI Public Key Certificate Analysis</h3>
              <p className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                RFC 5280 Trust Chain & Revocation Status Evaluation
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className={`p-1.5 rounded-lg border transition ${
              isDark ? 'hover:bg-slate-800 border-slate-700 text-slate-400' : 'hover:bg-slate-100 border-slate-200 text-slate-500'
            }`}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs">
          {/* Status banner */}
          <div className={`p-3.5 rounded-xl border flex items-center justify-between ${
            cert.status === 'VALID'
              ? isDark ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-200' : 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : isDark ? 'bg-rose-950/30 border-rose-500/30 text-rose-200' : 'bg-rose-50 border-rose-200 text-rose-900'
          }`}>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5" />
              <div>
                <span className="font-bold block">Status: {cert.status}</span>
                <span className="text-[11px] opacity-90">{cert.trust_chain_details}</span>
              </div>
            </div>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded border uppercase font-bold">
              {cert.validity_status}
            </span>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-2 gap-3 font-mono">
            <div className={`p-3 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <span className={`text-[10px] uppercase font-bold block mb-1 font-sans ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Subject DN</span>
              <span className="text-[11px] break-all text-cyan-400">{cert.subject}</span>
            </div>
            <div className={`p-3 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <span className={`text-[10px] uppercase font-bold block mb-1 font-sans ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Issuer DN</span>
              <span className="text-[11px] break-all">{cert.issuer}</span>
            </div>
            <div className={`p-3 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <span className={`text-[10px] uppercase font-bold block mb-1 font-sans ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Public Key Algo</span>
              <span className="text-[11px] text-emerald-400">{cert.public_key_algorithm} ({cert.public_key_size})</span>
            </div>
            <div className={`p-3 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <span className={`text-[10px] uppercase font-bold block mb-1 font-sans ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Signature Algo</span>
              <span className="text-[11px]">{cert.signature_algorithm}</span>
            </div>
            <div className={`p-3 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <span className={`text-[10px] uppercase font-bold block mb-1 font-sans ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Valid Period</span>
              <span className="text-[10px]">{cert.valid_from} &rarr; {cert.valid_until}</span>
            </div>
            <div className={`p-3 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
              <span className={`text-[10px] uppercase font-bold block mb-1 font-sans ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Serial Number</span>
              <span className="text-[10px]">{cert.serial_number}</span>
            </div>
          </div>

          {/* Fingerprint */}
          <div className={`p-3 rounded-lg border ${isDark ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
            <span className={`text-[10px] uppercase font-bold block mb-1 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>SHA-256 Fingerprint</span>
            <div className="font-mono text-[11px] break-all select-all text-slate-300">
              {cert.fingerprint_sha256}
            </div>
          </div>

          {/* Revocation check info */}
          <div className={`p-3 rounded-lg border flex items-center justify-between ${
            isDark ? 'bg-slate-900/60 border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'
          }`}>
            <div>
              <span className="font-bold block">Revocation (OCSP / CRL): {cert.revocation.status}</span>
              <span className="text-[11px] opacity-80">{cert.revocation.details}</span>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              {cert.revocation.method}
            </span>
          </div>

          {/* Warnings if any */}
          {cert.security_warnings.length > 0 && (
            <div className={`p-3 rounded-lg border text-xs space-y-1 ${
              isDark ? 'bg-amber-950/30 border-amber-500/30 text-amber-300' : 'bg-amber-50 border-amber-200 text-amber-800'
            }`}>
              <span className="font-bold flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Security Warnings:
              </span>
              <ul className="list-disc list-inside space-y-0.5 text-[11px]">
                {cert.security_warnings.map((w, idx) => (
                  <li key={idx}>{w}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className={`px-5 py-3 border-t flex justify-end ${
          isDark ? 'border-slate-800 bg-slate-900/50' : 'border-slate-200 bg-slate-50'
        }`}>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
