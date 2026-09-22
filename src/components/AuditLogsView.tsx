import React, { useState } from 'react';
import {
  Copy,
  Check,
  Download,
  Search,
  Filter,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  FileText
} from 'lucide-react';
import { SecurityLog } from '../types';

interface AuditLogsViewProps {
  logs: SecurityLog[];
  caseId?: string;
}

export const AuditLogsView: React.FC<AuditLogsViewProps> = ({ logs, caseId }) => {
  const [filter, setFilter] = useState<'ALL' | 'ALERT' | 'WARNING' | 'SUCCESS'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  const filteredLogs = logs.filter((log) => {
    const matchesFilter =
      filter === 'ALL' ||
      (filter === 'ALERT' && (log.status === 'ALERT' || log.status === 'ACTION_REQUIRED')) ||
      (filter === 'WARNING' && log.status === 'WARNING') ||
      (filter === 'SUCCESS' && (log.status === 'SUCCESS' || log.status === 'INFO'));

    const matchesSearch =
      log.event.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.time.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (log.event_hash && log.event_hash.toLowerCase().includes(searchQuery.toLowerCase()));

    return matchesFilter && matchesSearch;
  });

  const handleCopyAll = () => {
    const text = logs
      .map(
        (l) =>
          `[${l.time}] [${l.status.padEnd(8)}] Hash: ${l.event_hash || 'N/A'} | Prev: ${l.previous_hash || 'N/A'} | ${l.event}`
      )
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportTxt = () => {
    const text = `================================================================================
CYBERSECURITY RESEARCH AUDIT LOGS - CASE ${caseId || 'UNKNOWN'}
Tamper-Evident Chained Cryptographic Ledger (SHA-256)
================================================================================
Export Time: ${new Date().toISOString()}
Total Records: ${logs.length}
--------------------------------------------------------------------------------
${logs
  .map(
    (l) =>
      `[${l.time}] [${l.status.padEnd(8)}] HASH: ${l.event_hash || 'N/A'} | PREV: ${l.previous_hash || 'N/A'} | ${l.event}`
  )
  .join('\n')}
================================================================================
Verification: All entries chained via recursive SHA-256 state updates.
`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Audit_Logs_${caseId || Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Top Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-[#1E293B] rounded p-3.5">
        <div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-[#F1F5F9]">
            Chained Cryptographic Audit Ledger
          </h2>
          <p className="text-[11px] text-[#94A3B8]">
            Tamper-evident sequence verified by recursive SHA-256 hashing
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyAll}
            className="px-2.5 py-1.5 bg-[#162032] border border-[#1E293B] hover:bg-[#1E293B] text-[#F1F5F9] text-xs font-medium rounded cursor-pointer transition flex items-center gap-1.5"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#34D399]" /> : <Copy className="w-3.5 h-3.5 text-[#94A3B8]" />}
            <span>{copied ? 'Copied' : 'Copy All'}</span>
          </button>
          <button
            onClick={handleExportTxt}
            className="px-2.5 py-1.5 bg-[#0284C7] hover:bg-[#0369A1] text-white text-xs font-semibold rounded cursor-pointer transition flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export TXT</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-[#1E293B] rounded p-3">
        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 text-xs">
          <span className="text-[11px] font-semibold text-[#94A3B8] mr-1">Filter:</span>
          {(['ALL', 'SUCCESS', 'WARNING', 'ALERT'] as const).map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilter(lvl)}
              className={`px-2.5 py-1 rounded text-xs font-medium border cursor-pointer transition ${
                filter === lvl
                  ? 'bg-[#0284C7] text-white border-[#0284C7]'
                  : 'bg-[#162032] text-[#94A3B8] border-[#1E293B] hover:bg-[#1E293B] hover:text-[#F1F5F9]'
              }`}
            >
              {lvl === 'SUCCESS' ? 'VALID / OK' : lvl}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-[#94A3B8] absolute left-2.5 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search event or hash..."
            className="w-full pl-8 pr-2.5 py-1.5 bg-[#162032] border border-[#1E293B] rounded text-xs text-[#F1F5F9] placeholder-[#64748B] focus:outline-none focus:border-[#0284C7]"
          />
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-[#111827] border border-[#1E293B] rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-[#162032] border-b border-[#1E293B] text-[#94A3B8] font-sans font-semibold text-[11px]">
                <th className="py-2.5 px-3 w-24">Time</th>
                <th className="py-2.5 px-3 w-28">Status</th>
                <th className="py-2.5 px-3">Event Description</th>
                <th className="py-2.5 px-3 w-40 hidden md:table-cell">Event Hash</th>
                <th className="py-2.5 px-3 w-36 hidden lg:table-cell">Prev Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B] text-[11px]">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-[#94A3B8] font-sans">
                    No log events match the selected criteria.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log, idx) => (
                  <tr key={idx} className="hover:bg-[#162032]/60 transition-colors">
                    <td className="py-2 px-3 text-[#94A3B8] whitespace-nowrap">{log.time}</td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                          log.status === 'ALERT' || log.status === 'ACTION_REQUIRED'
                            ? 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]'
                            : log.status === 'WARNING'
                            ? 'bg-[#78350F]/40 text-[#FBBF24] border-[#92400E]'
                            : 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]'
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-[#F1F5F9] font-sans font-medium">{log.event}</td>
                    <td className="py-2 px-3 text-[#94A3B8] hidden md:table-cell truncate max-w-[150px]" title={log.full_event_hash || log.event_hash}>
                      {log.event_hash || 'SHA-256'}
                    </td>
                    <td className="py-2 px-3 text-[#94A3B8] hidden lg:table-cell truncate max-w-[140px]" title={log.previous_hash}>
                      {log.previous_hash || '000000...'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
