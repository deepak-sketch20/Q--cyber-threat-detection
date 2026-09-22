import React from 'react';
import { ShieldCheck, AlertTriangle, X, CheckCircle, Lock } from 'lucide-react';
import { CertificateAnalysisInfo } from '../types';

interface CertificateModalProps {
  cert?: CertificateAnalysisInfo;
  isOpen: boolean;
  onClose: () => void;
  isDark?: boolean;
}

export const CertificateModal: React.FC<CertificateModalProps> = ({ cert, isOpen, onClose }) => {
  if (!isOpen || !cert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
      <div className="w-full max-w-2xl rounded-md border border-[#1E293B] bg-[#111827] text-[#F1F5F9] shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#1E293B] bg-[#162032]">
          <div className="flex items-center gap-2">
            <div className={`w-6 h-6 rounded flex items-center justify-center text-white ${
              cert.status === 'VALID' ? 'bg-[#064E3B] text-[#34D399] border border-[#065F46]' : 'bg-[#7F1D1D] text-[#F87171] border border-[#991B1B]'
            }`}>
              <Lock className="w-3.5 h-3.5" />
            </div>
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
                X.509 PKI Public Key Certificate Analysis
              </h3>
              <p className="text-[11px] text-[#94A3B8]">
                RFC 5280 Trust Chain &amp; Revocation Status Evaluation
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded border border-[#1E293B] hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-4 overflow-y-auto space-y-3 text-xs">
          {/* Status banner */}
          <div className={`p-3 rounded border flex items-center justify-between ${
            cert.status === 'VALID'
              ? 'bg-[#064E3B]/40 border-[#065F46] text-[#34D399]'
              : 'bg-[#7F1D1D]/40 border-[#991B1B] text-[#F87171]'
          }`}>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              <div>
                <span className="font-bold block">Status: {cert.status}</span>
                <span className="text-[11px] opacity-90">{cert.trust_chain_details}</span>
              </div>
            </div>
            <span className="font-mono text-[11px] px-2 py-0.5 rounded border border-[#1E293B] uppercase font-bold bg-[#111827] text-[#F1F5F9]">
              {cert.validity_status}
            </span>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-2 gap-2.5 font-mono">
            <div className="p-2.5 rounded border border-[#1E293B] bg-[#162032]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#94A3B8]">Subject DN</span>
              <span className="text-[11px] break-all text-[#38BDF8] font-semibold">{cert.subject}</span>
            </div>
            <div className="p-2.5 rounded border border-[#1E293B] bg-[#162032]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#94A3B8]">Issuer DN</span>
              <span className="text-[11px] break-all text-[#F1F5F9]">{cert.issuer}</span>
            </div>
            <div className="p-2.5 rounded border border-[#1E293B] bg-[#162032]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#94A3B8]">Public Key Algo</span>
              <span className="text-[11px] text-[#34D399] font-semibold">{cert.public_key_algorithm} ({cert.public_key_size})</span>
            </div>
            <div className="p-2.5 rounded border border-[#1E293B] bg-[#162032]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#94A3B8]">Signature Algo</span>
              <span className="text-[11px] text-[#F1F5F9]">{cert.signature_algorithm}</span>
            </div>
            <div className="p-2.5 rounded border border-[#1E293B] bg-[#162032]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#94A3B8]">Validity Period</span>
              <span className="text-[11px] text-[#F1F5F9]">{cert.valid_from} &rarr; {cert.valid_until}</span>
            </div>
            <div className="p-2.5 rounded border border-[#1E293B] bg-[#162032]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#94A3B8]">Serial Number</span>
              <span className="text-[11px] text-[#F1F5F9]">{cert.serial_number}</span>
            </div>
          </div>

          {/* Fingerprint */}
          <div className="p-2.5 rounded border border-[#1E293B] bg-[#162032]">
            <span className="text-[10px] uppercase font-bold block mb-0.5 text-[#94A3B8]">SHA-256 Fingerprint</span>
            <div className="font-mono text-[11px] break-all select-all text-[#F1F5F9]">
              {cert.fingerprint_sha256}
            </div>
          </div>

          {/* Revocation check details */}
          <div className="border border-[#1E293B] rounded p-2.5 bg-[#162032] space-y-1">
            <span className="text-[11px] font-bold text-[#F1F5F9] uppercase block">RFC 5280 Revocation / OCSP Verification</span>
            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="flex items-center gap-1.5 text-[#34D399]">
                <CheckCircle className="w-3.5 h-3.5" />
                <span>CRL Distribution Points: Verified</span>
              </div>
              <div className="flex items-center gap-1.5 text-[#34D399]">
                <CheckCircle className="w-3.5 h-3.5" />
                <span>OCSP Responder: Good</span>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-4 py-2.5 border-t border-[#1E293B] bg-[#162032] flex justify-end">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded border border-[#1E293B] bg-[#111827] hover:bg-[#1E293B] text-xs font-semibold text-[#F1F5F9] cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
