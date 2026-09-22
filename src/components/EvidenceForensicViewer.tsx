import React, { useState, useMemo } from 'react';
import {
  FileText,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Clock,
  Filter,
  Layers,
  Code2,
  ShieldAlert,
  Search
} from 'lucide-react';
import { EvidenceItem, EvidenceTimelineItem } from '../types';

interface EvidenceForensicViewerProps {
  evidence: EvidenceItem[];
  timeline?: EvidenceTimelineItem[];
  fileName: string;
  fileSize?: string;
  isSecure?: boolean;
  theme?: 'light' | 'dark';
}

export const EvidenceForensicViewer: React.FC<EvidenceForensicViewerProps> = ({
  evidence,
  timeline,
  fileName,
  fileSize,
  isSecure = false,
  theme = 'dark'
}) => {
  const isLight = theme === 'light';
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedThreat, setSelectedThreat] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'evidence' | 'timeline'>('evidence');
  const [expandedItems, setExpandedItems] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Toggle expand/collapse of an evidence item
  const toggleExpand = (id: string) => {
    setExpandedItems(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // Copy line content or snippet to clipboard
  const handleCopySnippet = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Unique threat types for filter
  const uniqueThreats = useMemo(() => {
    const set = new Set<string>();
    evidence.forEach(item => {
      if (item.threatType) set.add(item.threatType);
    });
    return Array.from(set);
  }, [evidence]);

  // Filtered evidence items
  const filteredEvidence = useMemo(() => {
    return evidence.filter(item => {
      if (selectedSeverity !== 'ALL' && item.severity !== selectedSeverity) return false;
      if (selectedThreat !== 'ALL' && item.threatType !== selectedThreat) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const inReason = item.reason.toLowerCase().includes(q);
        const inContent = (item.lineContent || '').toLowerCase().includes(q);
        const inField = (item.field || '').toLowerCase().includes(q);
        const inThreat = item.threatType.toLowerCase().includes(q);
        const inId = item.id.toLowerCase().includes(q);
        return inReason || inContent || inField || inThreat || inId;
      }
      return true;
    });
  }, [evidence, selectedSeverity, selectedThreat, searchQuery]);

  const severityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/15 text-red-400 border-red-500/30';
      case 'HIGH':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
    }
  };

  const locationTypeBadge = (item: EvidenceItem) => {
    switch (item.locationType) {
      case 'LINE':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
            Line {item.lineNumber}
          </span>
        );
      case 'MULTI_LINE':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/15 text-purple-300 border border-purple-500/30">
            Lines {item.lineNumbers ? item.lineNumbers.join(', ') : `Line ${item.lineNumber}`}
          </span>
        );
      case 'FIELD':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
            Field: {item.field} (Line {item.lineNumber})
          </span>
        );
      case 'FILE_LEVEL':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-sans bg-gray-500/20 text-gray-300 border border-gray-500/30 italic">
            File-Level Verification
          </span>
        );
      case 'BYTE_OFFSET':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
            Byte Range: {item.byteOffsetStart}–{item.byteOffsetEnd}
          </span>
        );
      case 'EVENT':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-blue-500/15 text-blue-300 border border-blue-500/30">
            Event Sequence (Line {item.lineNumber || 'N/A'})
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className={`border rounded-lg p-4 space-y-4 shadow-xs transition-colors ${
      isLight ? 'bg-white border-[#CBD5E1] text-[#0F172A]' : 'bg-[#111827] border-[#1E293B] text-[#F1F5F9]'
    }`}>
      {/* Header Section */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b pb-3.5 ${
        isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'
      }`}>
        <div>
          <div className="flex items-center gap-2">
            <span className={`p-1 rounded border ${
              isLight ? 'bg-[#F1F5F9] border-[#CBD5E1] text-[#0284C7]' : 'bg-[#162032] border-[#1E293B] text-[#38BDF8]'
            }`}>
              <Code2 className="w-4 h-4" />
            </span>
            <h3 className={`text-sm font-bold tracking-wide uppercase flex items-center gap-2 ${
              isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'
            }`}>
              Attack Evidence Location &amp; Line-Level Forensic Analysis
            </h3>
          </div>
          <p className={`text-xs mt-1 font-sans ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
            Cryptographic forensic mapping of threat indicators to exact source lines, structured fields, and correlation trails.
          </p>
        </div>

        {/* View mode toggle */}
        <div className={`flex items-center gap-1 border p-0.5 rounded text-xs font-medium ${
          isLight ? 'bg-[#F1F5F9] border-[#CBD5E1]' : 'bg-[#162032] border-[#1E293B]'
        }`}>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`px-3 py-1 rounded transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'evidence'
                ? (isLight ? 'bg-[#0284C7] text-white font-semibold' : 'bg-[#2457A6] text-white font-semibold')
                : (isLight ? 'text-[#475569] hover:text-[#0F172A]' : 'text-[#94A3B8] hover:text-[#F1F5F9]')
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Evidence Items ({evidence.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`px-3 py-1 rounded transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'timeline'
                ? (isLight ? 'bg-[#0284C7] text-white font-semibold' : 'bg-[#2457A6] text-white font-semibold')
                : (isLight ? 'text-[#475569] hover:text-[#0F172A]' : 'text-[#94A3B8] hover:text-[#F1F5F9]')
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Timeline ({timeline?.length || 0})</span>
          </button>
        </div>
      </div>

      {/* When no attacks or clean file */}
      {evidence.length === 0 && (
        <div className={`p-4 rounded-md text-xs font-mono space-y-2 border ${
          isLight ? 'bg-[#F0FDF4] border-[#86EFAC]' : 'bg-[#064E3B]/20 border-[#065F46]'
        }`}>
          <div className={`flex items-center gap-2 font-bold ${isLight ? 'text-[#15803D]' : 'text-[#34D399]'}`}>
            <CheckCircle2 className="w-4 h-4" />
            <span>NO ATTACK EVIDENCE DETECTED</span>
          </div>
          <p className={`leading-relaxed ${isLight ? 'text-[#334155]' : 'text-[#94A3B8]'}`}>
            All evaluated payload lines, transaction parameters, cryptographic digest calculations, and simulated quantum metrics strictly align with authentic baseline criteria. No tampered fields or reused nonces identified.
          </p>
          <div className={`pt-2 border-t flex items-center gap-4 text-[11px] ${
            isLight ? 'border-[#86EFAC]/60 text-[#475569]' : 'border-[#065F46]/50 text-[#64748B]'
          }`}>
            <span>Target: <strong className={isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}>{fileName}</strong></span>
            {fileSize && <span>Size: <strong className={isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}>{fileSize}</strong></span>}
            <span>Verification: <strong className={isLight ? 'text-[#15803D]' : 'text-[#34D399]'}>PASS (100% Match)</strong></span>
          </div>
        </div>
      )}

      {/* Filter and Search Bar (Active when evidence exists) */}
      {evidence.length > 0 && activeTab === 'evidence' && (
        <div className={`flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center justify-between text-xs p-2.5 rounded border ${
          isLight ? 'bg-[#F8FAFC] border-[#CBD5E1]' : 'bg-[#162032] border-[#1E293B]'
        }`}>
          <div className="flex flex-wrap items-center gap-2">
            <div className={`flex items-center gap-1 ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
              <Filter className="w-3.5 h-3.5" />
              <span className="font-semibold">Filter:</span>
            </div>

            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={e => setSelectedSeverity(e.target.value)}
              className={`border rounded px-2 py-1 font-mono focus:outline-none focus:border-[#0284C7] ${
                isLight ? 'bg-white border-[#CBD5E1] text-[#0F172A]' : 'bg-[#111827] border-[#1E293B] text-[#F1F5F9]'
              }`}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Threat Type Filter */}
            {uniqueThreats.length > 1 && (
              <select
                value={selectedThreat}
                onChange={e => setSelectedThreat(e.target.value)}
                className={`border rounded px-2 py-1 font-mono focus:outline-none focus:border-[#0284C7] ${
                  isLight ? 'bg-white border-[#CBD5E1] text-[#0F172A]' : 'bg-[#111827] border-[#1E293B] text-[#F1F5F9]'
                }`}
              >
                <option value="ALL">All Threat Types</option>
                {uniqueThreats.map(t => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Search box */}
          <div className="relative flex-1 sm:max-w-xs">
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search line, field, or token..."
              className={`w-full border rounded pl-7 pr-2 py-1 font-mono focus:outline-none focus:border-[#0284C7] ${
                isLight 
                  ? 'bg-white border-[#CBD5E1] text-[#0F172A] placeholder:text-[#94A3B8]' 
                  : 'bg-[#111827] border-[#1E293B] text-[#F1F5F9] placeholder:text-[#64748B]'
              }`}
            />
            <Search className={`w-3.5 h-3.5 absolute left-2 top-2 ${isLight ? 'text-[#64748B]' : 'text-[#64748B]'}`} />
          </div>
        </div>
      )}

      {/* EVIDENCE CARDS LIST VIEW */}
      {activeTab === 'evidence' && evidence.length > 0 && (
        <div className="space-y-3">
          {filteredEvidence.map((item, idx) => {
            const isExpanded = expandedItems[item.id] ?? true; // Default open for immediate clarity
            const isCopied = copiedId === item.id;

            return (
              <div
                key={item.id}
                className={isLight ? 'bg-white border-[#CBD5E1] rounded-lg overflow-hidden transition shadow-xs' : 'bg-[#162032] border-[#1E293B] rounded-lg overflow-hidden transition'}
              >
                {/* Card Title Bar */}
                <div className={isLight ? 'p-3 bg-[#F8FAFC] border-b border-[#E2E8F0] flex flex-col sm:flex-row sm:items-center justify-between gap-2' : 'p-3 bg-[#111827] border-b border-[#1E293B] flex flex-col sm:flex-row sm:items-center justify-between gap-2'}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[#0284C7] dark:text-[#38BDF8]">
                      #{item.id}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border uppercase ${severityBadgeClass(
                        item.severity
                      )}`}
                    >
                      {item.severity}
                    </span>
                    <span className={`text-xs font-bold ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                      {item.threatType}
                    </span>
                    {locationTypeBadge(item)}

                    {item.isContributingEvidence && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-sans bg-blue-500/20 text-blue-600 dark:text-blue-300 border border-blue-500/30">
                        Contributing Telemetry
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {item.lineContent && (
                      <button
                        onClick={() => handleCopySnippet(item.id, item.lineContent || '')}
                        className={`px-2 py-1 rounded text-[11px] font-sans border cursor-pointer flex items-center gap-1 transition ${
                          isLight 
                            ? 'border-[#CBD5E1] bg-white hover:bg-[#F1F5F9] text-[#475569] hover:text-[#0F172A]' 
                            : 'border-[#1E293B] bg-[#162032] hover:bg-[#1E293B] text-[#94A3B8] hover:text-[#F1F5F9]'
                        }`}
                        title="Copy culprit line snippet"
                      >
                        {isCopied ? (
                          <>
                            <Check className="w-3 h-3 text-[#16A34A] dark:text-[#34D399]" />
                            <span className="text-[#16A34A] dark:text-[#34D399]">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy Snippet</span>
                          </>
                        )}
                      </button>
                    )}

                    <button
                      onClick={() => toggleExpand(item.id)}
                      className={`p-1 rounded cursor-pointer ${
                        isLight ? 'text-[#64748B] hover:text-[#0F172A] hover:bg-[#E2E8F0]' : 'text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#1E293B]'
                      }`}
                      title={isExpanded ? 'Collapse' : 'Expand'}
                    >
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Card Body */}
                {isExpanded && (
                  <div className={`p-3 space-y-3 text-xs ${isLight ? 'bg-white' : ''}`}>
                    {/* Reason & Detector Info */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                      <div>
                        <span className={`text-[10px] uppercase font-bold tracking-wider block ${
                          isLight ? 'text-[#475569]' : 'text-[#64748B]'
                        }`}>
                          Detection Justification
                        </span>
                        <p className={`mt-0.5 font-medium leading-relaxed ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                          {item.reason}
                        </p>
                      </div>
                      <div>
                        <span className={`text-[10px] uppercase font-bold tracking-wider block ${
                          isLight ? 'text-[#475569]' : 'text-[#64748B]'
                        }`}>
                          Detection Subsystem
                        </span>
                        <p className={`mt-0.5 font-mono ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
                          {item.detector}
                        </p>
                      </div>
                    </div>

                    {/* Code Snippet & Line Gutter Display */}
                    {item.lineContent ? (
                      <div className="space-y-1">
                        <span className="text-[10px] uppercase font-bold text-[#64748B] tracking-wider block">
                          Source Code / Payload Context
                        </span>

                        <div className="bg-[#0B0F19] rounded border border-[#1E293B] overflow-hidden font-mono text-[11px]">
                          {/* Context Before */}
                          {item.contextBefore && item.contextBefore.length > 0 && (
                            <div className="opacity-60 divide-y divide-[#1E293B]/40">
                              {item.contextBefore.map(ctx => (
                                <div key={ctx.lineNumber} className="flex hover:bg-[#111827]">
                                  <span className="w-12 py-1 pr-3 text-right text-[#64748B] select-none bg-[#0B0F19] border-r border-[#1E293B]">
                                    {ctx.lineNumber}
                                  </span>
                                  <span className="py-1 px-3 text-[#94A3B8] whitespace-pre truncate">
                                    {ctx.content}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Culprit Line (Highlighted in High-Contrast Red/Amber) */}
                          <div className="flex bg-red-950/40 border-y border-red-500/40 text-red-200">
                            <span className="w-12 py-1.5 pr-3 text-right font-bold text-red-400 select-none bg-red-950/60 border-r border-red-500/40">
                              {item.lineNumber || '!!'}
                            </span>
                            <span className="py-1.5 px-3 font-semibold whitespace-pre truncate text-red-200 flex-1">
                              {item.lineContent}
                            </span>
                            <span className="px-2 py-0.5 my-auto mr-2 text-[10px] uppercase font-bold tracking-wider rounded bg-red-500/30 text-red-300">
                              ATTACK EVIDENCE
                            </span>
                          </div>

                          {/* Context After */}
                          {item.contextAfter && item.contextAfter.length > 0 && (
                            <div className="opacity-60 divide-y divide-[#1E293B]/40">
                              {item.contextAfter.map(ctx => (
                                <div key={ctx.lineNumber} className="flex hover:bg-[#111827]">
                                  <span className="w-12 py-1 pr-3 text-right text-[#64748B] select-none bg-[#0B0F19] border-r border-[#1E293B]">
                                    {ctx.lineNumber}
                                  </span>
                                  <span className="py-1 px-3 text-[#94A3B8] whitespace-pre truncate">
                                    {ctx.content}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : item.locationType === 'FILE_LEVEL' ? (
                      <div className="p-2.5 bg-[#111827] rounded border border-[#1E293B] text-[#94A3B8] italic">
                        The evidence is derived from file-level cryptographic verification against calculated SHA-256 digest and public key PKI validation. No isolated textual token caused the failure; the cryptographic envelope as a whole is invalid.
                      </div>
                    ) : null}

                    {/* Related Correlated Lines (e.g. Replay Duplicates across Line 23 and Line 81) */}
                    {item.relatedEvidence && item.relatedEvidence.length > 0 && (
                      <div className={`pt-2 border-t space-y-1.5 ${isLight ? 'border-[#E2E8F0]' : 'border-[#1E293B]'}`}>
                        <span className={`text-[10px] uppercase font-bold tracking-wider block ${
                          isLight ? 'text-[#475569]' : 'text-[#64748B]'
                        }`}>
                          Correlated Multi-Line Evidence
                        </span>
                        <div className="space-y-1">
                          {item.relatedEvidence.map((rel, rIdx) => (
                            <div
                              key={rIdx}
                              className={`p-2 rounded border text-xs font-mono flex items-center justify-between gap-2 ${
                                isLight ? 'bg-[#F8FAFC] border-[#CBD5E1]' : 'bg-[#111827] border-[#1E293B]'
                              }`}
                            >
                              <div className="flex items-center gap-2">
                                <span className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-600 dark:text-purple-300 text-[10px]">
                                  Line {rel.lineNumber}
                                </span>
                                <span className={`font-medium truncate ${isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}`}>
                                  {rel.lineContent || `Field: ${rel.field}`}
                                </span>
                              </div>
                              <span className={`text-[11px] shrink-0 ${isLight ? 'text-[#475569]' : 'text-[#94A3B8]'}`}>
                                {rel.reason}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Explanatory Reasoning Trail ("Why this verdict?") */}
                    {item.explanation && item.explanation.length > 0 && (
                      <div className={`p-2.5 rounded border space-y-1.5 ${
                        isLight ? 'bg-[#F8FAFC] border-[#CBD5E1]' : 'bg-[#111827] border-[#1E293B]'
                      }`}>
                        <span className={`text-[10px] uppercase font-bold tracking-wider block ${
                          isLight ? 'text-[#0284C7]' : 'text-[#38BDF8]'
                        }`}>
                          Forensic Reasoning Trail (Why this verdict?)
                        </span>
                        <ol className={`list-decimal list-inside space-y-1 text-xs font-sans ${
                          isLight ? 'text-[#475569]' : 'text-[#94A3B8]'
                        }`}>
                          {item.explanation.map((step, sIdx) => (
                            <li key={sIdx} className="leading-relaxed">
                              <span className={isLight ? 'text-[#0F172A]' : 'text-[#F1F5F9]'}>{step}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* TIMELINE VIEW */}
      {activeTab === 'timeline' && (
        <div className="space-y-2">
          {(!timeline || timeline.length === 0) ? (
            <div className="p-4 bg-[#162032] border border-[#1E293B] rounded text-center text-xs text-[#94A3B8]">
              No sequential security timeline events recorded.
            </div>
          ) : (
            <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1E293B]">
              {timeline.map((evt, idx) => (
                <div key={evt.id || idx} className="relative group">
                  {/* Dot */}
                  <div
                    className={`absolute -left-6 top-1 w-3.5 h-3.5 rounded-full border-2 bg-[#111827] ${
                      evt.severity === 'CRITICAL'
                        ? 'border-red-500 bg-red-950'
                        : evt.severity === 'HIGH'
                        ? 'border-amber-500 bg-amber-950'
                        : 'border-[#38BDF8] bg-[#162032]'
                    }`}
                  />

                  <div className="bg-[#162032] border border-[#1E293B] rounded p-3 text-xs space-y-1 group-hover:border-[#38BDF8]/50 transition">
                    <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                      <div className="flex items-center gap-2">
                        <span className="text-[#38BDF8] font-bold">{evt.id}</span>
                        {evt.lineNumber && (
                          <span className="px-1.5 py-0.2 rounded bg-indigo-500/20 text-indigo-300">
                            Line {evt.lineNumber}
                          </span>
                        )}
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${severityBadgeClass(evt.severity)}`}>
                          {evt.severity}
                        </span>
                      </div>
                      <span className="text-[#64748B]">
                        {evt.hasTimestamp && evt.time ? evt.time : 'Sequence Indexed'}
                      </span>
                    </div>

                    <p className="text-[#F1F5F9] font-medium leading-relaxed">
                      {evt.event}
                    </p>

                    {evt.rawRecord && (
                      <div className="mt-1.5 p-1.5 bg-[#0B0F19] rounded border border-[#1E293B] font-mono text-[11px] text-red-300 truncate">
                        {evt.rawRecord}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
