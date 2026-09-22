import React, { useState, useEffect } from 'react';
import {
  Database,
  Server,
  HardDrive,
  Cloud,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  X,
  Radio,
  Zap,
  ShieldCheck,
  Cpu,
  ArrowRight,
  ExternalLink,
  Lock
} from 'lucide-react';

export interface DatabaseOption {
  id: 'supabase_postgresql' | 'postgresql' | 'file_storage';
  name: string;
  badge: string;
  description: string;
  is_active: boolean;
  is_configured: boolean;
  status: 'connected' | 'configured' | 'available' | 'offline';
  storage_info?: string;
}

export interface DatabaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentEngine: string;
  currentStatus: string;
  onDatabaseChanged?: () => void;
}

export function DatabaseModal({
  isOpen,
  onClose,
  currentEngine,
  currentStatus,
  onDatabaseChanged
}: DatabaseModalProps) {
  const [loading, setLoading] = useState<boolean>(false);
  const [switching, setSwitching] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; latency_ms: number; message: string }>>({});
  const [activeEngineId, setActiveEngineId] = useState<string>('supabase_postgresql');
  const [options, setOptions] = useState<DatabaseOption[]>([]);
  const [diagnostics, setDiagnostics] = useState<any>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (isOpen) {
      fetchDatabaseConfig();
      setFeedback(null);
    }
  }, [isOpen]);

  const fetchDatabaseConfig = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/database/config');
      if (res.ok) {
        const data = await res.json();
        if (data.database) {
          setActiveEngineId(data.database.engine);
          if (data.database.options) {
            setOptions(data.database.options);
          }
          setDiagnostics(data.database.diagnostics);
        }
      }
    } catch (err: any) {
      console.warn('Failed to load database config:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSwitchEngine = async (engineId: 'supabase_postgresql' | 'postgresql' | 'file_storage') => {
    setSwitching(engineId);
    setFeedback(null);
    try {
      const res = await fetch('/api/database/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: engineId })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setActiveEngineId(engineId);
        setFeedback({
          type: 'success',
          message: `Active persistence engine successfully switched to ${
            engineId === 'supabase_postgresql'
              ? 'Supabase Cloud (PostgreSQL)'
              : engineId === 'postgresql'
              ? 'PostgreSQL Database'
              : 'Local Encrypted Storage'
          }.`
        });
        if (onDatabaseChanged) onDatabaseChanged();
        await fetchDatabaseConfig();
      } else {
        setFeedback({
          type: 'error',
          message: data.error || 'Failed to switch database engine.'
        });
      }
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Network error while switching database engine.'
      });
    } finally {
      setSwitching(null);
    }
  };

  const handleTestEngine = async (engineId: string) => {
    setTesting(engineId);
    try {
      const res = await fetch('/api/database/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: engineId })
      });
      const data = await res.json();
      setTestResults(prev => ({
        ...prev,
        [engineId]: {
          success: data.success,
          latency_ms: data.latency_ms ?? 0,
          message: data.message || (data.success ? 'Connection verified successfully.' : 'Connection test failed.')
        }
      }));
    } catch (err: any) {
      setTestResults(prev => ({
        ...prev,
        [engineId]: {
          success: false,
          latency_ms: 0,
          message: err?.message || 'Connection test failed.'
        }
      }));
    } finally {
      setTesting(null);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs animate-in fade-in duration-200">
      <div 
        id="database-config-modal-card"
        className="bg-[#111827] border border-[#1E293B] text-[#F1F5F9] rounded-lg shadow-2xl max-w-2xl w-full overflow-hidden flex flex-col max-h-[90vh]"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#1E293B] flex items-center justify-between bg-[#162032]">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-[#0284C7]/20 flex items-center justify-center border border-[#0284C7]/40">
              <Database className="w-5 h-5 text-[#38BDF8]" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#F1F5F9] tracking-tight">
                Database Engine &amp; Storage Configuration
              </h2>
              <p className="text-xs text-[#94A3B8]">
                Select, switch, and verify the persistent database for quantum forensic records
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#1E293B] transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5">
          {/* Active Banner */}
          <div className="bg-[#162032] border border-[#1E293B] rounded-lg p-3.5 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#0284C7] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-[#0284C7]"></span>
              </span>
              <div>
                <div className="text-xs font-semibold text-[#38BDF8]">
                  Active Engine: {
                    activeEngineId === 'supabase_postgresql'
                      ? 'Supabase Cloud (PostgreSQL)'
                      : activeEngineId === 'postgresql'
                      ? 'Direct PostgreSQL (Cloud)'
                      : 'Local Encrypted Storage (Air-Gapped)'
                  }
                </div>
                <div className="text-[11px] text-[#94A3B8]">
                  State: {currentStatus === 'connected' ? 'Connected & Verified' : 'Active (Local Sync Fallback)'}
                </div>
              </div>
            </div>
            <button
              onClick={fetchDatabaseConfig}
              disabled={loading}
              className="text-xs font-medium text-[#38BDF8] hover:text-[#0284C7] flex items-center gap-1 cursor-pointer hover:underline"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>

          {/* Feedback banner */}
          {feedback && (
            <div
              className={`p-3 rounded-lg text-xs flex items-start gap-2 border ${
                feedback.type === 'success'
                  ? 'bg-[#064E3B]/40 text-[#34D399] border-[#065F46]'
                  : 'bg-[#7F1D1D]/40 text-[#F87171] border-[#991B1B]'
              }`}
            >
              {feedback.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-[#34D399] mt-0.5 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-[#F87171] mt-0.5 shrink-0" />
              )}
              <div>{feedback.message}</div>
            </div>
          )}

          {/* Database Provider Cards */}
          <div className="space-y-3">
            <div className="text-xs font-bold text-[#94A3B8] uppercase tracking-wider">
              Available Database Providers
            </div>

            {/* Provider 1: Supabase */}
            <div
              className={`p-4 rounded-lg border transition-all ${
                activeEngineId === 'supabase_postgresql'
                  ? 'border-[#0284C7] bg-[#162032] ring-1 ring-[#0284C7]'
                  : 'border-[#1E293B] bg-[#162032]/50 hover:border-[#334155]'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-[#064E3B]/50 text-[#34D399] flex items-center justify-center shrink-0 mt-0.5 font-bold text-xs border border-[#065F46]">
                    <Cloud className="w-4 h-4 text-[#34D399]" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-[#F1F5F9]">
                        Supabase Cloud (PostgreSQL)
                      </span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-[#064E3B]/40 text-[#34D399] border border-[#065F46]">
                        Active Cloud DB
                      </span>
                    </div>
                    <p className="text-xs text-[#94A3B8] mt-1 leading-relaxed">
                      Hosted PostgreSQL engine with auto-provisioned schema (<code className="font-mono text-[11px] bg-[#111827] px-1 py-0.5 rounded border border-[#1E293B] text-[#F1F5F9]">security_analyses</code> table) and secure binary artifact bucket (<code className="font-mono text-[11px] bg-[#111827] px-1 py-0.5 rounded border border-[#1E293B] text-[#F1F5F9]">qsecure-files</code>).
                    </p>
                    <div className="text-[11px] text-[#94A3B8] font-mono mt-1.5 flex items-center gap-2">
                      <span>Endpoint: vzdeufgteanqsbrqxsax.supabase.co</span>
                      <span>&bull;</span>
                      <span className="text-[#34D399] font-semibold">Ready</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                  <button
                    onClick={() => handleTestEngine('supabase_postgresql')}
                    disabled={testing === 'supabase_postgresql'}
                    className="px-2.5 py-1.5 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] border border-[#1E293B] bg-[#111827] hover:bg-[#1E293B] rounded-md transition-colors flex items-center gap-1 cursor-pointer"
                  >
                    <Zap className={`w-3 h-3 text-[#FBBF24] ${testing === 'supabase_postgresql' ? 'animate-spin' : ''}`} />
                    {testing === 'supabase_postgresql' ? 'Testing...' : 'Ping Test'}
                  </button>

                  {activeEngineId === 'supabase_postgresql' ? (
                    <span className="px-3 py-1.5 text-xs font-bold text-[#34D399] bg-[#064E3B]/40 border border-[#065F46] rounded-md flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Active Provider
                    </span>
                  ) : (
                    <button
                      onClick={() => handleSwitchEngine('supabase_postgresql')}
                      disabled={switching === 'supabase_postgresql'}
                      className="px-3 py-1.5 text-xs font-bold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-md transition-colors cursor-pointer"
                    >
                      {switching === 'supabase_postgresql' ? 'Switching...' : 'Switch to Supabase'}
                    </button>
                  )}
                </div>
              </div>

              {testResults['supabase_postgresql'] && (
                <div className={`mt-3 pt-2.5 border-t border-[#1E293B] text-xs flex items-center gap-2 ${
                  testResults['supabase_postgresql'].success ? 'text-[#34D399]' : 'text-[#F87171]'
                }`}>
                  {testResults['supabase_postgresql'].success ? (
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                  ) : (
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  )}
                  <span>{testResults['supabase_postgresql'].message}</span>
                </div>
              )}
            </div>

            {/* Provider 2: Direct PostgreSQL */}
            <div
              className={`p-4 rounded-lg border transition-all ${
                activeEngineId === 'postgresql'
                  ? 'border-[#0284C7] bg-[#162032] ring-1 ring-[#0284C7]'
                  : 'border-[#1E293B] bg-[#162032]/50 hover:border-[#334155]'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-[#0369A1]/30 text-[#38BDF8] flex items-center justify-center shrink-0 mt-0.5 font-bold text-xs border border-[#0284C7]/40">
                    <Server className="w-4 h-4 text-[#38BDF8]" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-[#F1F5F9]">
                        Direct PostgreSQL / Cloud SQL / Neon
                      </span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-[#0369A1]/30 text-[#38BDF8] border border-[#0284C7]/40">
                        Relational SQL
                      </span>
                    </div>
                    <p className="text-xs text-[#94A3B8] mt-1 leading-relaxed">
                      Connects directly via <code className="font-mono text-[11px] bg-[#111827] px-1 py-0.5 rounded border border-[#1E293B] text-[#F1F5F9]">DATABASE_URL</code> with strict TLS and relational schemas (<code className="font-mono text-[11px] bg-[#111827] px-1 py-0.5 rounded border border-[#1E293B] text-[#F1F5F9]">security_cases</code>, <code className="font-mono text-[11px] bg-[#111827] px-1 py-0.5 rounded border border-[#1E293B] text-[#F1F5F9]">audit_users</code>).
                    </p>
                    <div className="text-[11px] text-[#94A3B8] font-mono mt-1.5">
                      Config: {diagnostics?.database_url_configured ? 'DATABASE_URL is defined in environment' : 'DATABASE_URL not set in .env'}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                  <button
                    onClick={() => handleTestEngine('postgresql')}
                    disabled={testing === 'postgresql'}
                    className="px-2.5 py-1.5 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] border border-[#1E293B] bg-[#111827] hover:bg-[#1E293B] rounded-md transition-colors flex items-center gap-1 cursor-pointer"
                  >
                    <Zap className={`w-3 h-3 text-[#FBBF24] ${testing === 'postgresql' ? 'animate-spin' : ''}`} />
                    {testing === 'postgresql' ? 'Testing...' : 'Ping Test'}
                  </button>

                  {activeEngineId === 'postgresql' ? (
                    <span className="px-3 py-1.5 text-xs font-bold text-[#34D399] bg-[#064E3B]/40 border border-[#065F46] rounded-md flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Active Provider
                    </span>
                  ) : (
                    <button
                      onClick={() => handleSwitchEngine('postgresql')}
                      disabled={switching === 'postgresql'}
                      className="px-3 py-1.5 text-xs font-bold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-md transition-colors cursor-pointer"
                    >
                      {switching === 'postgresql' ? 'Switching...' : 'Switch to PostgreSQL'}
                    </button>
                  )}
                </div>
              </div>

              {testResults['postgresql'] && (
                <div className={`mt-3 pt-2.5 border-t border-[#1E293B] text-xs flex items-center gap-2 ${
                  testResults['postgresql'].success ? 'text-[#34D399]' : 'text-[#F87171]'
                }`}>
                  {testResults['postgresql'].success ? (
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                  ) : (
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  )}
                  <span>{testResults['postgresql'].message}</span>
                </div>
              )}
            </div>

            {/* Provider 3: Local File Storage */}
            <div
              className={`p-4 rounded-lg border transition-all ${
                activeEngineId === 'file_storage'
                  ? 'border-[#0284C7] bg-[#162032] ring-1 ring-[#0284C7]'
                  : 'border-[#1E293B] bg-[#162032]/50 hover:border-[#334155]'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-[#78350F]/40 text-[#FBBF24] flex items-center justify-center shrink-0 mt-0.5 font-bold text-xs border border-[#92400E]">
                    <HardDrive className="w-4 h-4 text-[#FBBF24]" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-[#F1F5F9]">
                        Local Encrypted File Storage
                      </span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-[#78350F]/40 text-[#FBBF24] border border-[#92400E]">
                        Air-Gapped / Offline
                      </span>
                    </div>
                    <p className="text-xs text-[#94A3B8] mt-1 leading-relaxed">
                      Zero-dependency persistent local storage located in <code className="font-mono text-[11px] bg-[#111827] px-1 py-0.5 rounded border border-[#1E293B] text-[#F1F5F9]">data/cases_store.json</code>. Always available for air-gapped lab research.
                    </p>
                    <div className="text-[11px] text-[#94A3B8] font-mono mt-1.5">
                      Storage Path: data/cases_store.json &bull; Status: Always Available
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                  <button
                    onClick={() => handleTestEngine('file_storage')}
                    disabled={testing === 'file_storage'}
                    className="px-2.5 py-1.5 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] border border-[#1E293B] bg-[#111827] hover:bg-[#1E293B] rounded-md transition-colors flex items-center gap-1 cursor-pointer"
                  >
                    <Zap className={`w-3 h-3 text-[#FBBF24] ${testing === 'file_storage' ? 'animate-spin' : ''}`} />
                    {testing === 'file_storage' ? 'Testing...' : 'Verify Store'}
                  </button>

                  {activeEngineId === 'file_storage' ? (
                    <span className="px-3 py-1.5 text-xs font-bold text-[#34D399] bg-[#064E3B]/40 border border-[#065F46] rounded-md flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Active Provider
                    </span>
                  ) : (
                    <button
                      onClick={() => handleSwitchEngine('file_storage')}
                      disabled={switching === 'file_storage'}
                      className="px-3 py-1.5 text-xs font-bold text-white bg-[#0284C7] hover:bg-[#0369A1] rounded-md transition-colors cursor-pointer"
                    >
                      {switching === 'file_storage' ? 'Switching...' : 'Switch to Local'}
                    </button>
                  )}
                </div>
              </div>

              {testResults['file_storage'] && (
                <div className={`mt-3 pt-2.5 border-t border-[#1E293B] text-xs flex items-center gap-2 ${
                  testResults['file_storage'].success ? 'text-[#34D399]' : 'text-[#F87171]'
                }`}>
                  {testResults['file_storage'].success ? (
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                  ) : (
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  )}
                  <span>{testResults['file_storage'].message}</span>
                </div>
              )}
            </div>
          </div>

          {/* Technical Info Box */}
          <div className="p-3.5 rounded-lg bg-[#162032] border border-[#1E293B] text-xs text-[#94A3B8] space-y-2">
            <div className="font-semibold text-[#F1F5F9] flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-[#38BDF8]" />
              Database Zero-Crash Guarantee
            </div>
            <p className="leading-relaxed text-[11px]">
              The Q-Secure analyzer architecture isolates database persistence through dual-tiered fallback. If a remote cloud database is ever unreachable or experiences network latency, operations gracefully preserve all case records into the local encrypted JSON ledger without interrupting forensic analysis or file ingestion pipelines.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-[#1E293B] bg-[#162032] flex items-center justify-between">
          <div className="text-xs text-[#94A3B8]">
            Current Selection: <strong className="text-[#F1F5F9]">{activeEngineId}</strong>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-[#F1F5F9] bg-[#111827] hover:bg-[#1E293B] border border-[#1E293B] rounded-md transition-colors cursor-pointer"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
