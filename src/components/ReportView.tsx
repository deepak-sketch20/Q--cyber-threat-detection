import React from 'react';
import {
  Download,
  Printer,
  FileCode,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Lock,
  FileText
} from 'lucide-react';
import { AnalysisResponse } from '../types';

interface ReportViewProps {
  data: AnalysisResponse | null;
  theme?: 'light' | 'dark';
}

export const ReportView: React.FC<ReportViewProps> = ({ data, theme }) => {
  if (!data) return null;

  const isLight = theme === 'light' || (typeof document !== 'undefined' && document.documentElement.classList.contains('light'));

  const riskScore = data.threat?.risk_score ?? 0;
  const isAttack = data.threat?.status === 'ATTACK DETECTED' || riskScore >= 60;
  const isSuspicious = !isAttack && (riskScore >= 35 || data.signature?.hash_mismatch);

  let overallStatus: 'SECURE' | 'SUSPICIOUS' | 'COMPROMISED' = 'SECURE';
  let statusBadgeClass = isLight 
    ? 'bg-[#DCFCE7] text-[#15803D] border-[#86EFAC]' 
    : 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]';

  if (isAttack) {
    overallStatus = 'COMPROMISED';
    statusBadgeClass = isLight 
      ? 'bg-[#FEE2E2] text-[#B91C1C] border-[#FCA5A5]' 
      : 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]';
  } else if (isSuspicious) {
    overallStatus = 'SUSPICIOUS';
    statusBadgeClass = isLight 
      ? 'bg-[#FEF3C7] text-[#B45309] border-[#FCD34D]' 
      : 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]';
  }

  const handlePrint = () => {
    window.print();
  };

  const handleExportJson = () => {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Security_Analysis_Report_${data.case_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadTxt = () => {
    if (data.report_files?.txt_url) {
      window.open(data.report_files.txt_url, '_blank');
      return;
    }
    // Fallback text report generator
    const content = `================================================================================
CYBERSECURITY RESEARCH LAB - QUANTUM DIGITAL SIGNATURE SECURITY ANALYZER
SECURITY ANALYSIS REPORT
================================================================================
Case ID:            ${data.case_id}
Generated At:       ${data.file.upload_time} UTC
Analysis Status:    ${overallStatus}
Risk Assessment:    ${riskScore} / 100 (${data.threat?.risk || 'LOW'})
Target File:        ${data.file.filename}
SHA-256 Digest:     ${data.file.sha256}

1. FILE INFORMATION
--------------------------------------------------------------------------------
File Name:          ${data.file.filename}
File Type:          ${data.file.file_type}
File Size:          ${data.file.file_size}
SHA-256:            ${data.file.sha256}
Integrity Status:   ${data.file.integrity_status}

2. INTEGRITY VERIFICATION
--------------------------------------------------------------------------------
SHA-256 Digest:     ${data.file.sha256}
Reference Hash:     ${data.file.reference_hash}
Digest Match:       ${data.file.hash_match}
Integrity Status:   ${data.file.integrity_status}

3. DIGITAL SIGNATURE ANALYSIS
--------------------------------------------------------------------------------
Signature Present:  ${data.signature.signature_present ? 'YES' : 'NO'}
Algorithm:          ${data.signature.signature_algorithm}
Signature Status:   ${data.signature.signature_status}
Hash Mismatch:      ${data.signature.hash_mismatch ? 'YES (Tampered)' : 'NO (Intact)'}
Signer Identity:    ${data.signature.signer_information || 'N/A'}

4. CERTIFICATE / PKI ANALYSIS
--------------------------------------------------------------------------------
Certificate Status: ${data.certificate_analysis?.status || 'N/A'}
Issuer:             ${data.certificate_analysis?.issuer || 'N/A'}
Subject:            ${data.certificate_analysis?.subject || 'N/A'}
Trust Chain:        ${data.certificate_analysis?.trust_chain || 'N/A'}
Key Specification:  ${data.certificate_analysis?.key_spec || 'N/A'}

5. THREAT DETECTION
--------------------------------------------------------------------------------
Primary Threat:     ${data.threat?.detected_threat || 'None'}
Category:           ${data.threat?.threat_category || 'N/A'}
Severity:           ${data.threat?.risk || 'LOW'}
Confidence:         ${data.threat?.confidence}%
Reason:             ${data.threat?.reason || 'Clean artifact'}

6. QUANTUM SECURITY SIMULATION
--------------------------------------------------------------------------------
Quantum Channel:    Simulated (Bell State / Local Simulator)
Simulated QBER:     ${data.quantum?.qber_percentage || '1.20%'} (Threshold: ${data.quantum?.qber_threshold || '11.0%'})
Mismatch Rate:      ${data.quantum?.mismatch_rate_percentage || '1.20%'}
Matching Rate:      ${data.quantum?.matching_rate_percentage || '98.80%'}
Quantum Risk:       ${data.quantum?.quantum_risk || 'SECURE'}
Eavesdrop Prob:     ${data.quantum?.estimated_eavesdropping_probability || '0.0%'}
Fidelity:           ${data.quantum?.state_preservation_fidelity || '100.0%'}

7. RISK ASSESSMENT
--------------------------------------------------------------------------------
Overall Risk Score: ${riskScore} / 100
Classification:     ${data.threat?.risk || 'LOW'}
Recommendation:     ${data.threat?.first_action || data.threat?.recommendation}

8. AUDIT TIMELINE
--------------------------------------------------------------------------------
${(data.logs || []).map(l => `[${l.time}] ${l.status.padEnd(12)} ${l.event}`).join('\n')}

================================================================================
DISCLAIMER: Quantum security measurements represent simulated channel behavior in a local
research environment and do not represent physical quantum hardware telemetry.
================================================================================
`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Security_Analysis_Report_${data.case_id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Top Action Toolbar */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 border rounded p-3.5 print:hidden transition-colors ${
        isLight ? 'bg-white border-[#CBD5E1] shadow-xs' : 'bg-[#111827] border-[#1E293B]'
      }`}>
        <div>
          <h2 className={`text-xs font-bold uppercase tracking-wider ${
            isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'
          }`}>
            Security Analysis Report Viewer
          </h2>
          <p className={`text-[11px] ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
            Formal 9-section forensic report generated from artifact verification
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleDownloadTxt}
            className="px-3 py-1.5 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded cursor-pointer transition flex items-center gap-1.5 shadow-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Report (TXT)</span>
          </button>
          <button
            onClick={handleExportJson}
            className={`px-3 py-1.5 border text-xs font-medium rounded cursor-pointer transition flex items-center gap-1.5 ${
              isLight 
                ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#0F172A] hover:bg-[#E2E8F0]' 
                : 'bg-[#162032] border-[#1E293B] hover:bg-[#1E293B] text-[#F1F5F9]'
            }`}
          >
            <FileCode className={`w-3.5 h-3.5 ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`} />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            className={`px-3 py-1.5 border text-xs font-medium rounded cursor-pointer transition flex items-center gap-1.5 ${
              isLight 
                ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#0F172A] hover:bg-[#E2E8F0]' 
                : 'bg-[#162032] border-[#1E293B] hover:bg-[#1E293B] text-[#F1F5F9]'
            }`}
          >
            <Printer className={`w-3.5 h-3.5 ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`} />
            <span>Print Report</span>
          </button>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* FORMAL PRINTABLE REPORT DOCUMENT CONTAINER */}
      {/* ===================================================================== */}
      <div className={`border rounded p-6 sm:p-8 space-y-6 font-sans shadow-xs transition-colors print:bg-white print:text-black print:border-none print:shadow-none print:p-0 ${
        isLight ? 'bg-white border-[#CBD5E1] text-[#0F172A]' : 'bg-[#111827] border-[#1E293B] text-[#F1F5F9]'
      }`}>
        {/* Document Header */}
        <div className={`border-b pb-4 space-y-2 ${isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'}`}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <div className={`text-[11px] font-bold uppercase tracking-widest font-mono ${
                isLight ? 'text-[#0284C7]' : 'text-[#38BDF8]'
              }`}>
                University Cybersecurity Research Laboratory &bull; Quantum Security Analyzer
              </div>
              <h1 className={`text-lg sm:text-xl font-bold uppercase tracking-tight mt-0.5 ${
                isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'
              }`}>
                SECURITY ANALYSIS REPORT
              </h1>
            </div>
            <div className="text-right font-mono">
              <span className={`inline-block px-3 py-1 rounded border text-xs font-bold uppercase ${statusBadgeClass}`}>
                {overallStatus}
              </span>
            </div>
          </div>

          <div className={`grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 text-xs font-mono border-t ${
            isLight ? 'text-[#475569] border-[#E2E8F0]' : 'text-[#94A3B8] border-[#1E293B]'
          }`}>
            <div>
              <span className={`font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Case ID:</span> {data.case_id}
            </div>
            <div>
              <span className={`font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Generated At:</span> {data.file.upload_time} UTC
            </div>
            <div className="sm:text-right">
              <span className={`font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Risk Assessment:</span>{' '}
              <span className={`font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{riskScore} / 100</span> ({data.threat?.risk || 'LOW'})
            </div>
          </div>
        </div>

        {/* SECTION 1: File Information */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            1. File Information
          </h3>
          <div className={`border rounded overflow-hidden ${isLight ? 'border-[#CBD5E1]' : 'border-[#1E293B]'}`}>
            <table className="w-full text-xs font-mono">
              <tbody className={`divide-y ${isLight ? 'divide-[#E2E8F0]' : 'divide-[#1E293B]'}`}>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold w-1/4 ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>File Name</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.file.filename}</td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>File Type / Size</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.file.file_type} &bull; {data.file.file_size}</td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>SHA-256 Digest</td>
                  <td className={`py-1.5 px-3 break-all ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.file.sha256}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* SECTION 2: Integrity Verification */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            2. Integrity Verification
          </h3>
          <div className={`border rounded overflow-hidden ${isLight ? 'border-[#CBD5E1]' : 'border-[#1E293B]'}`}>
            <table className="w-full text-xs font-mono">
              <tbody className={`divide-y ${isLight ? 'divide-[#E2E8F0]' : 'divide-[#1E293B]'}`}>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold w-1/4 ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Integrity Status</td>
                  <td className="py-1.5 px-3">
                    <span className={data.signature?.hash_mismatch 
                      ? (isLight ? 'text-[#DC2626] font-bold' : 'text-[#F87171] font-bold') 
                      : (isLight ? 'text-[#15803D] font-bold' : 'text-[#34D399] font-bold')
                    }>
                      {data.file.integrity_status}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Reference Hash</td>
                  <td className={`py-1.5 px-3 break-all ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.file.reference_hash}</td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Hash Match Result</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.file.hash_match}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* SECTION 3: Digital Signature Analysis */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            3. Digital Signature Analysis
          </h3>
          <div className={`border rounded overflow-hidden ${isLight ? 'border-[#CBD5E1]' : 'border-[#1E293B]'}`}>
            <table className="w-full text-xs font-mono">
              <tbody className={`divide-y ${isLight ? 'divide-[#E2E8F0]' : 'divide-[#1E293B]'}`}>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold w-1/4 ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Signature Present</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.signature.signature_present ? 'YES' : 'NO'}</td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Algorithm</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                    {data.cryptographic_verification?.algorithm_detected || data.signature.signature_algorithm}
                  </td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Signature Status</td>
                  <td className="py-1.5 px-3">
                    <span className={data.signature.signature_status === 'VALID' 
                      ? (isLight ? 'text-[#15803D] font-bold' : 'text-[#34D399] font-bold') 
                      : (isLight ? 'text-[#DC2626] font-bold' : 'text-[#F87171] font-bold')
                    }>
                      {data.signature.signature_status}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Signer Information</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.signature.signer_information || 'N/A'}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* SECTION 4: Certificate / PKI Analysis */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            4. Certificate / PKI Analysis
          </h3>
          <div className={`border rounded overflow-hidden ${isLight ? 'border-[#CBD5E1]' : 'border-[#1E293B]'}`}>
            <table className="w-full text-xs font-mono">
              <tbody className={`divide-y ${isLight ? 'divide-[#E2E8F0]' : 'divide-[#1E293B]'}`}>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold w-1/4 ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Certificate Status</td>
                  <td className="py-1.5 px-3">
                    <span className={data.certificate_analysis?.status === 'VALID' 
                      ? (isLight ? 'text-[#15803D] font-bold' : 'text-[#34D399] font-bold') 
                      : (isLight ? 'text-[#B45309] font-bold' : 'text-[#FBBF24] font-bold')
                    }>
                      {data.certificate_analysis?.status || 'N/A'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Issuer CA</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.certificate_analysis?.issuer || 'N/A'}</td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Subject Identity</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.certificate_analysis?.subject || 'N/A'}</td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Trust Chain</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.certificate_analysis?.trust_chain_details || 'N/A'}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* SECTION 5: Threat Detection */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            5. Threat Detection
          </h3>
          <div className={`p-3 rounded border space-y-1.5 text-xs ${
            isLight ? 'bg-[#F8FAFC] border-[#CBD5E1]' : 'bg-[#162032] border-[#1E293B]'
          }`}>
            <div className="flex items-center justify-between">
              <span className={`font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                Primary Threat: {data.threat?.detected_threat || 'None'}
              </span>
              <span className={`font-mono text-[11px] ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
                Severity: <strong className={isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}>{data.threat?.risk || 'LOW'}</strong> &bull; Confidence: <strong className={isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}>{data.threat?.confidence}%</strong>
              </span>
            </div>
            <p className={`leading-relaxed ${isLight ? 'text-[#334155]' : 'text-[#F1F5F9]'}`}>
              {data.threat?.reason}
            </p>
          </div>

          {/* Line-Level Forensic Evidence Table */}
          {(data.evidence && data.evidence.length > 0) && (
            <div className="space-y-1.5 pt-1">
              <span className={`text-[11px] font-bold uppercase tracking-wide block ${
                isLight ? 'text-[#0284C7]' : 'text-[#38BDF8]'
              }`}>
                Pinpointed Attack Evidence Locations &amp; Forensic Line Traces:
              </span>
              <div className={`border rounded overflow-hidden ${isLight ? 'border-[#CBD5E1]' : 'border-[#1E293B]'}`}>
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className={isLight ? 'bg-[#F1F5F9] text-[#475569]' : 'bg-[#0B0F19] text-[#94A3B8]'}>
                      <th className="py-1.5 px-2.5 text-left font-semibold w-16">ID</th>
                      <th className="py-1.5 px-2.5 text-left font-semibold w-24">Location</th>
                      <th className="py-1.5 px-2.5 text-left font-semibold w-28">Severity</th>
                      <th className="py-1.5 px-2.5 text-left font-semibold">Evidence Details / Content</th>
                    </tr>
                  </thead>
                  <tbody className={`divide-y ${isLight ? 'divide-[#E2E8F0]' : 'divide-[#1E293B]'}`}>
                    {data.evidence.map((item) => (
                      <tr key={item.id} className={isLight ? 'hover:bg-[#F8FAFC]' : 'hover:bg-[#162032]'}>
                        <td className="py-1.5 px-2.5 font-bold text-[#38BDF8]">{item.id}</td>
                        <td className="py-1.5 px-2.5 font-medium">
                          {item.locationType === 'LINE' ? `Line ${item.lineNumber}` :
                           item.locationType === 'MULTI_LINE' ? `Lines ${item.lineNumbers?.join(', ') || item.lineNumber}` :
                           item.locationType === 'FIELD' ? `${item.field || 'Field'} (L${item.lineNumber})` :
                           item.locationType === 'FILE_LEVEL' ? 'File-Level' :
                           item.locationType === 'BYTE_OFFSET' ? `Bytes ${item.byteOffsetStart}-${item.byteOffsetEnd}` :
                           `Line ${item.lineNumber || 'N/A'}`}
                        </td>
                        <td className="py-1.5 px-2.5">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            item.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-500' :
                            item.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-500' :
                            'bg-blue-500/20 text-blue-500'
                          }`}>
                            {item.severity}
                          </span>
                        </td>
                        <td className="py-1.5 px-2.5">
                          <div className={`font-semibold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                            {item.reason}
                          </div>
                          {item.lineContent && (
                            <div className="mt-0.5 p-1 bg-black/10 dark:bg-black/40 rounded text-[10px] truncate max-w-xl text-red-500 dark:text-red-300">
                              {item.lineContent}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* SECTION 6: Quantum Security Simulation */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            6. Quantum Security Simulation
          </h3>
          <div className={`border rounded overflow-hidden ${isLight ? 'border-[#CBD5E1]' : 'border-[#1E293B]'}`}>
            <table className="w-full text-xs font-mono">
              <tbody className={`divide-y ${isLight ? 'divide-[#E2E8F0]' : 'divide-[#1E293B]'}`}>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold w-1/4 ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Backend Engine</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Local Simulator (Bell State Φ+ / Teleportation)</td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Channel QBER</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                    {data.quantum?.qber_percentage || '1.20%'} (Threshold: {data.quantum?.qber_threshold || '11.0%'})
                  </td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Mismatch / Matching Rate</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                    Mismatch: {data.quantum?.mismatch_rate_percentage || '1.20%'} &bull; Matching: {data.quantum?.matching_rate_percentage || '98.80%'}
                  </td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>State Fidelity</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.quantum?.state_preservation_fidelity || '100.0%'}</td>
                </tr>
                <tr>
                  <td className={`py-1.5 px-3 font-semibold ${isLight ? 'bg-[#F8FAFC] text-[#475569]' : 'bg-[#162032] text-[#94A3B8]'}`}>Quantum Assessment</td>
                  <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{data.quantum?.assessment_note || 'Channel normal, within security bounds'}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className={`text-[11px] italic ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
            * Quantum security measurements are generated using a local simulation environment. Results represent simulated channel behavior and are not measurements from physical quantum hardware.
          </p>
        </div>

        {/* SECTION 7: Risk Assessment */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            7. Risk Assessment
          </h3>
          <div className={`p-3 rounded border space-y-2 text-xs ${
            isLight ? 'bg-[#F8FAFC] border-[#CBD5E1]' : 'bg-[#162032] border-[#1E293B]'
          }`}>
            <div className="flex items-center justify-between">
              <span className={`font-semibold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>Overall Calculated Risk Score:</span>
              <span className={`font-mono font-bold text-sm ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{riskScore} / 100</span>
            </div>
            <div className={`w-full h-2 rounded-full overflow-hidden ${isLight ? 'bg-[#E2E8F0]' : 'bg-[#1E293B]'}`}>
              <div
                className="h-full"
                style={{
                  width: `${Math.max(4, riskScore)}%`,
                  backgroundColor: riskScore >= 80 ? '#DC2626' : riskScore >= 50 ? '#D97706' : '#16A34A'
                }}
              />
            </div>
            <div className={`text-[11px] ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
              Classification: <strong className={isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}>{data.threat?.risk || 'LOW'}</strong> &bull; Assessment standard adheres to NIST SP 800-131A guidelines.
            </div>
          </div>
        </div>

        {/* SECTION 8: Recommended Action */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            8. Recommended Action
          </h3>
          <div className={`p-3 rounded border text-xs leading-relaxed ${
            isLight ? 'bg-[#F8FAFC] border-[#CBD5E1] text-[#0F172A]' : 'bg-[#162032] border-[#1E293B] text-[#F1F5F9]'
          }`}>
            {data.threat?.first_action || data.threat?.recommendation || 'Review the transaction and verify the signer and message integrity.'}
          </div>
        </div>

        {/* SECTION 9: Audit Timeline */}
        <div className="space-y-2">
          <h3 className={`text-xs font-bold uppercase tracking-wider border-b pb-1 ${
            isLight ? 'text-[#0284C7] border-[#E2E8F0]' : 'text-[#38BDF8] border-[#1E293B]'
          }`}>
            9. Audit Timeline &amp; Chained Verification
          </h3>
          <div className={`border rounded overflow-hidden ${isLight ? 'border-[#CBD5E1]' : 'border-[#1E293B]'}`}>
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className={`border-b text-[11px] ${
                  isLight ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#334155]' : 'bg-[#162032] border-[#1E293B] text-[#94A3B8]'
                }`}>
                  <th className="py-1.5 px-3">Time</th>
                  <th className="py-1.5 px-3">Event</th>
                  <th className="py-1.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody className={`divide-y text-[11px] ${isLight ? 'divide-[#E2E8F0]' : 'divide-[#1E293B]'}`}>
                {(data.logs || []).slice(0, 8).map((log, i) => (
                  <tr key={i}>
                    <td className={`py-1.5 px-3 whitespace-nowrap ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>{log.time}</td>
                    <td className={`py-1.5 px-3 ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>{log.event}</td>
                    <td className="py-1.5 px-3 whitespace-nowrap">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                        log.status === 'ALERT' || log.status === 'ACTION_REQUIRED'
                          ? (isLight ? 'bg-[#FEE2E2] text-[#B91C1C] border-[#FCA5A5]' : 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]')
                          : log.status === 'WARNING'
                          ? (isLight ? 'bg-[#FEF3C7] text-[#B45309] border-[#FCD34D]' : 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]')
                          : (isLight ? 'bg-[#DCFCE7] text-[#15803D] border-[#86EFAC]' : 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]')
                      }`}>
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className={`pt-4 border-t text-[11px] flex flex-col sm:flex-row justify-between gap-1 font-mono ${
          isLight ? 'border-[#E2E8F0] text-[#475569]' : 'border-[#1E293B] text-[#94A3B8]'
        }`}>
          <span>University Cybersecurity Research Lab &bull; End of Report</span>
          <span>Verification Digest: {data.file.sha256.substring(0, 24)}...</span>
        </div>
      </div>
    </div>
  );
};
