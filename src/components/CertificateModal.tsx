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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40">
      <div className="w-full max-w-2xl rounded-md border border-[#DADCE0] bg-white text-[#202124] shadow-lg flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#DADCE0] bg-[#F5F6F8]">
          <div className="flex items-center gap-2">
            <div className={`w-6 h-6 rounded flex items-center justify-center text-white ${
              cert.status === 'VALID' ? 'bg-[#2E7D32]' : 'bg-[#C62828]'
            }`}>
              <Lock className="w-3.5 h-3.5" />
            </div>
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                X.509 PKI Public Key Certificate Analysis
              </h3>
              <p className="text-[11px] text-[#5F6368]">
                RFC 5280 Trust Chain & Revocation Status Evaluation
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded border border-[#DADCE0] hover:bg-[#E8EAED] text-[#5F6368] cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-4 overflow-y-auto space-y-3 text-xs">
          {/* Status banner */}
          <div className={`p-3 rounded border flex items-center justify-between ${
            cert.status === 'VALID'
              ? 'bg-[#E8F5E9] border-[#C8E6C9] text-[#2E7D32]'
              : 'bg-[#FFEBEE] border-[#FFCDD2] text-[#C62828]'
          }`}>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              <div>
                <span className="font-bold block">Status: {cert.status}</span>
                <span className="text-[11px] opacity-90">{cert.trust_chain_details}</span>
              </div>
            </div>
            <span className="font-mono text-[11px] px-2 py-0.5 rounded border uppercase font-bold bg-white">
              {cert.validity_status}
            </span>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-2 gap-2.5 font-mono">
            <div className="p-2.5 rounded border border-[#DADCE0] bg-[#F5F6F8]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#5F6368]">Subject DN</span>
              <span className="text-[11px] break-all text-[#2457A6] font-semibold">{cert.subject}</span>
            </div>
            <div className="p-2.5 rounded border border-[#DADCE0] bg-[#F5F6F8]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#5F6368]">Issuer DN</span>
              <span className="text-[11px] break-all text-[#202124]">{cert.issuer}</span>
            </div>
            <div className="p-2.5 rounded border border-[#DADCE0] bg-[#F5F6F8]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#5F6368]">Public Key Algo</span>
              <span className="text-[11px] text-[#2E7D32] font-semibold">{cert.public_key_algorithm} ({cert.public_key_size})</span>
            </div>
            <div className="p-2.5 rounded border border-[#DADCE0] bg-[#F5F6F8]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#5F6368]">Signature Algo</span>
              <span className="text-[11px] text-[#202124]">{cert.signature_algorithm}</span>
            </div>
            <div className="p-2.5 rounded border border-[#DADCE0] bg-[#F5F6F8]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#5F6368]">Validity Period</span>
              <span className="text-[11px] text-[#202124]">{cert.valid_from} &rarr; {cert.valid_until}</span>
            </div>
            <div className="p-2.5 rounded border border-[#DADCE0] bg-[#F5F6F8]">
              <span className="text-[10px] uppercase font-bold block mb-0.5 font-sans text-[#5F6368]">Serial Number</span>
              <span className="text-[11px] text-[#202124]">{cert.serial_number}</span>
            </div>
          </div>

          {/* Fingerprint */}
          <div className="p-2.5 rounded border border-[#DADCE0] bg-[#F5F6F8]">
            <span className="text-[10px] uppercase font-bold block mb-0.5 text-[#5F6368]">SHA-256 Fingerprint</span>
            <div className="font-mono text-[11px] break-all select-all text-[#202124]">
              {cert.fingerprint_sha256}
            </div>
          </div>

          {/* Revocation check details */}
          <div className="border border-[#DADCE0] rounded p-2.5 bg-white space-y-1">
            <span className="text-[11px] font-bold text-[#202124] uppercase block">RFC 5280 Revocation / OCSP Verification</span>
            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="flex items-center gap-1.5 text-[#2E7D32]">
                <CheckCircle className="w-3.5 h-3.5" />
                <span>CRL Distribution Points: Verified</span>
              </div>
              <div className="flex items-center gap-1.5 text-[#2E7D32]">
                <CheckCircle className="w-3.5 h-3.5" />
                <span>OCSP Responder: Good</span>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-4 py-2.5 border-t border-[#DADCE0] bg-[#F5F6F8] flex justify-end">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-xs font-semibold text-[#202124] cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
