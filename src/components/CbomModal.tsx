import React, { useState } from 'react';
import { FileCode, Download, Copy, Check, X } from 'lucide-react';
import { CBOMData } from '../types';

interface CbomModalProps {
  cbom?: CBOMData;
  isOpen: boolean;
  onClose: () => void;
  isDark: boolean;
}

export const CbomModal: React.FC<CbomModalProps> = ({ cbom, isOpen, onClose, isDark }) => {
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className={`w-full max-w-3xl rounded-xl border shadow-2xl flex flex-col max-h-[90vh] overflow-hidden ${
        isDark ? 'bg-[#0f172a] border-slate-700 text-slate-100' : 'bg-white border-slate-200 text-slate-900'
      }`}>
        {/* Header */}
        <div className={`flex items-center justify-between px-5 py-4 border-b ${
          isDark ? 'border-slate-800 bg-slate-900/80' : 'border-slate-200 bg-slate-50'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              isDark ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-900 text-white'
            }`}>
              <FileCode className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold">CycloneDX Cryptography Bill of Materials (CBOM)</h3>
              <p className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                Specification v1.6 &bull; Automated Cryptographic Asset Inventory
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

        {/* Content */}
        <div className="p-5 overflow-y-auto space-y-4 font-mono text-xs">
          <div className={`p-3 rounded-lg border flex items-center justify-between ${
            isDark ? 'bg-slate-900 border-slate-800 text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'
          }`}>
            <div>
              <span className="font-bold text-cyan-400">Spec Format:</span> CycloneDX v1.6 &nbsp;|&nbsp;
              <span className="font-bold text-cyan-400"> Serial:</span> {cbom.serialNumber.substring(0, 24)}...
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className={`px-2.5 py-1 rounded text-xs font-sans font-semibold border flex items-center gap-1 transition ${
                  isDark ? 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200' : 'bg-white hover:bg-slate-100 border-slate-300 text-slate-700'
                }`}
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy JSON'}
              </button>
              <button
                onClick={handleDownload}
                className="px-2.5 py-1 rounded text-xs font-sans font-semibold bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1 transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download JSON
              </button>
            </div>
          </div>

          <pre className={`p-4 rounded-xl border overflow-x-auto max-h-[50vh] text-[11px] leading-relaxed ${
            isDark ? 'bg-slate-950 border-slate-800 text-emerald-300' : 'bg-slate-900 border-slate-800 text-emerald-400'
          }`}>
            {cbomJsonString}
          </pre>
        </div>

        {/* Footer */}
        <div className={`px-5 py-3 border-t flex justify-between items-center text-xs ${
          isDark ? 'border-slate-800 bg-slate-900/50 text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-500'
        }`}>
          <span>Adheres to CycloneDX Cryptographic Assets standard for quantum migration.</span>
          <button
            onClick={onClose}
            className={`px-3 py-1.5 rounded-lg font-semibold border ${
              isDark ? 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200' : 'bg-white hover:bg-slate-100 border-slate-300 text-slate-700'
            }`}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
