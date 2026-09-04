import React, { useState } from 'react';
import { FileCode, Download, Copy, Check, X } from 'lucide-react';
import { CBOMData } from '../types';

interface CbomModalProps {
  cbom?: CBOMData;
  isOpen: boolean;
  onClose: () => void;
  isDark?: boolean;
}

export const CbomModal: React.FC<CbomModalProps> = ({ cbom, isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !cbom) return null;

  const cbomJsonString = JSON.stringify(cbom, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(cbomJsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([cbomJsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyclonedx_cbom_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40">
      <div className="w-full max-w-3xl rounded-md border border-[#DADCE0] bg-white text-[#202124] shadow-lg flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#DADCE0] bg-[#F5F6F8]">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-[#2457A6] text-white flex items-center justify-center">
              <FileCode className="w-3.5 h-3.5" />
            </div>
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#202124]">
                CycloneDX Cryptography Bill of Materials (CBOM)
              </h3>
              <p className="text-[11px] text-[#5F6368]">
                Specification v1.6 &bull; Automated Cryptographic Asset Inventory
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

        {/* Content */}
        <div className="p-4 overflow-y-auto space-y-3 font-mono text-xs">
          <div className="p-2.5 rounded border border-[#DADCE0] bg-[#F5F6F8] flex items-center justify-between">
            <div className="text-[11px]">
              <span className="font-bold text-[#202124]">Format:</span> CycloneDX v1.6 &nbsp;|&nbsp;
              <span className="font-bold text-[#202124]"> Serial:</span> {cbom.serialNumber.substring(0, 24)}...
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={handleCopy}
                className="px-2.5 py-1 rounded text-xs font-sans font-medium border border-[#DADCE0] bg-white hover:bg-[#F5F6F8] text-[#202124] flex items-center gap-1 cursor-pointer transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-[#2E7D32]" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy JSON'}
              </button>
              <button
                onClick={handleDownload}
                className="px-2.5 py-1 rounded text-xs font-sans font-semibold bg-[#2457A6] hover:bg-[#1E4B8F] text-white flex items-center gap-1 cursor-pointer transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download JSON
              </button>
            </div>
          </div>

          <pre className="p-3 rounded border border-[#DADCE0] bg-[#F5F6F8] text-[#202124] overflow-x-auto max-h-[50vh] text-[11px] leading-relaxed">
            {cbomJsonString}
          </pre>

          {/* Table summary */}
          <div className="border border-[#DADCE0] rounded overflow-hidden">
            <table className="w-full text-left text-xs border-collapse font-sans">
              <thead>
                <tr className="bg-[#F5F6F8] border-b border-[#DADCE0] text-[#5F6368] font-bold">
                  <th className="py-1.5 px-3">Asset Type</th>
                  <th className="py-1.5 px-3">Name / Algorithm</th>
                  <th className="py-1.5 px-3">OID / Classical Security</th>
                  <th className="py-1.5 px-3">PQC Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#DADCE0] font-mono text-[11px]">
                {(cbom.components || []).map((c, i) => (
                  <tr key={i} className="hover:bg-[#F5F6F8]">
                    <td className="py-1.5 px-3 text-[#5F6368]">{c.type}</td>
                    <td className="py-1.5 px-3 font-semibold text-[#202124]">{c.name}</td>
                    <td className="py-1.5 px-3 text-[#5F6368]">{c.cryptoProperties?.oid || c.cryptoProperties?.algorithmProperties?.classicalSecurityLevel || 'N/A'}</td>
                    <td className="py-1.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                        c.cryptoProperties?.algorithmProperties?.nistQuantumSecurityLevel
                          ? 'bg-[#E8F5E9] text-[#2E7D32] border-[#C8E6C9]'
                          : 'bg-[#FFF3E0] text-[#B26A00] border-[#FFE0B2]'
                      }`}>
                        {c.cryptoProperties?.algorithmProperties?.nistQuantumSecurityLevel ? 'PQC NIST Standard' : 'Vulnerable to Shor\'s'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
