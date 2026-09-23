import React from 'react';
import {
  LayoutDashboard,
  Shield,
  Zap,
  Cpu,
  FileText,
  Terminal,
  FileCode,
  Lock,
  Mail,
  X,
  Layers,
  ChevronRight
} from 'lucide-react';

export type NavTabId = 'dashboard' | 'analyzer' | 'attack-sim' | 'quantum-lab' | 'reports' | 'audit-logs';

interface LeftSidebarProps {
  activeTab: NavTabId;
  setActiveTab: (tab: NavTabId) => void;
  theme: 'dark' | 'light';
  mobileOpen: boolean;
  setMobileOpen: (open: boolean) => void;
  onOpenCbom?: () => void;
  onOpenCert?: () => void;
  onOpenEmailAlert?: () => void;
}

export const NAV_ITEMS: { id: NavTabId; label: string; icon: React.ComponentType<{ className?: string }>; description: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, description: 'SOC Overview & Metrics' },
  { id: 'analyzer', label: 'Security Analyzer', icon: Shield, description: 'File & Hash Verification' },
  { id: 'attack-sim', label: 'Attack Simulation', icon: Zap, description: 'Threat Vectors & Forgery' },
  { id: 'quantum-lab', label: 'Quantum Security', icon: Cpu, description: 'Statevector & QDS Labs' },
  { id: 'reports', label: 'Reports', icon: FileText, description: 'Forensic PDF & Cases' },
  { id: 'audit-logs', label: 'Audit Logs', icon: Terminal, description: 'Immutable SOC Audit Trail' },
];

export function LeftSidebar({
  activeTab,
  setActiveTab,
  theme,
  mobileOpen,
  setMobileOpen,
  onOpenCbom,
  onOpenCert,
  onOpenEmailAlert
}: LeftSidebarProps) {
  const handleSelectTab = (tabId: NavTabId) => {
    setActiveTab(tabId);
    setMobileOpen(false);
  };

  const sidebarContent = (
    <div className={`w-[260px] min-w-[260px] h-full flex flex-col justify-between select-none ${
      theme === 'light'
        ? 'bg-white border-r border-[#CBD5E1] text-[#0F172A]'
        : 'bg-[#0E1526] border-r border-[#1E293B] text-[#F1F5F9]'
    }`}>
      {/* Top Header Section inside Sidebar */}
      <div>
        <div className={`p-4 border-b flex items-center justify-between ${
          theme === 'light' ? 'border-[#E2E8F0]' : 'border-[#1E293B]'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className={`w-7 h-7 rounded flex items-center justify-center shrink-0 border ${
              theme === 'light' ? 'bg-[#E0F2FE] border-[#BAE6FD]' : 'bg-[#0284C7]/20 border-[#0284C7]/30'
            }`}>
              <Layers className={`w-3.5 h-3.5 ${theme === 'light' ? 'text-[#0284C7]' : 'text-[#38BDF8]'}`} />
            </div>
            <div>
              <div className="text-xs font-bold uppercase tracking-wider">Navigation</div>
              <div className={`text-[10px] font-mono ${theme === 'light' ? 'text-[#64748B]' : 'text-[#64748B]'}`}>
                Q-SHIELD Modules
              </div>
            </div>
          </div>
          {/* Mobile Close Button */}
          <button
            onClick={() => setMobileOpen(false)}
            className={`md:hidden p-1 rounded border ${
              theme === 'light'
                ? 'border-[#CBD5E1] hover:bg-[#F1F5F9] text-[#475569]'
                : 'border-[#1E293B] hover:bg-[#1E293B] text-[#94A3B8]'
            }`}
            aria-label="Close Sidebar"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Primary Navigation List */}
        <nav className="p-3 space-y-1">
          <div className={`px-2 py-1 text-[10px] font-mono uppercase font-semibold tracking-wider ${
            theme === 'light' ? 'text-[#64748B]' : 'text-[#64748B]'
          }`}>
            Core Operations
          </div>
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-md text-xs font-medium transition cursor-pointer text-left group ${
                  isActive
                    ? theme === 'light'
                      ? 'bg-[#E0F2FE] text-[#0284C7] font-semibold border border-[#BAE6FD] shadow-xs'
                      : 'bg-[#0284C7]/20 text-[#38BDF8] font-semibold border border-[#0284C7]/40 shadow-xs'
                    : theme === 'light'
                      ? 'border border-transparent text-[#334155] hover:bg-[#F1F5F9] hover:text-[#0F172A]'
                      : 'border border-transparent text-[#94A3B8] hover:bg-[#131B2E] hover:text-[#F1F5F9]'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 shrink-0 transition-colors ${
                    isActive
                      ? theme === 'light' ? 'text-[#0284C7]' : 'text-[#38BDF8]'
                      : theme === 'light' ? 'text-[#64748B] group-hover:text-[#0F172A]' : 'text-[#64748B] group-hover:text-[#F1F5F9]'
                  }`} />
                  <div>
                    <div className="leading-snug">{item.label}</div>
                    <div className={`text-[10px] font-normal leading-none mt-0.5 ${
                      isActive
                        ? theme === 'light' ? 'text-[#0369A1]' : 'text-[#7DD3FC]'
                        : theme === 'light' ? 'text-[#94A3B8]' : 'text-[#64748B]'
                    }`}>
                      {item.description}
                    </div>
                  </div>
                </div>
                {isActive && (
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                    theme === 'light' ? 'bg-[#0284C7]' : 'bg-[#38BDF8]'
                  }`} />
                )}
              </button>
            );
          })}
        </nav>

        {/* Quick Action Forensics Utilities */}
        <div className={`p-3 border-t mt-2 space-y-1.5 ${
          theme === 'light' ? 'border-[#E2E8F0]' : 'border-[#1E293B]'
        }`}>
          <div className={`px-2 py-1 text-[10px] font-mono uppercase font-semibold tracking-wider ${
            theme === 'light' ? 'text-[#64748B]' : 'text-[#64748B]'
          }`}>
            Forensic Utilities
          </div>
          {onOpenCbom && (
            <button
              onClick={() => {
                onOpenCbom();
                setMobileOpen(false);
              }}
              className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs transition cursor-pointer border ${
                theme === 'light'
                  ? 'border-[#CBD5E1] bg-white hover:bg-[#F1F5F9] text-[#0F172A]'
                  : 'border-[#1E293B] bg-[#131B2E] hover:bg-[#1E293B] text-[#E2E8F0]'
              }`}
              title="View CycloneDX Cryptography Bill of Materials"
            >
              <div className="flex items-center gap-2">
                <FileCode className={`w-3.5 h-3.5 ${theme === 'light' ? 'text-[#0284C7]' : 'text-[#38BDF8]'}`} />
                <span className="font-medium">CBOM Inventory</span>
              </div>
              <ChevronRight className="w-3 h-3 text-[#64748B]" />
            </button>
          )}

          {onOpenCert && (
            <button
              onClick={() => {
                onOpenCert();
                setMobileOpen(false);
              }}
              className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs transition cursor-pointer border ${
                theme === 'light'
                  ? 'border-[#CBD5E1] bg-white hover:bg-[#F1F5F9] text-[#0F172A]'
                  : 'border-[#1E293B] bg-[#131B2E] hover:bg-[#1E293B] text-[#E2E8F0]'
              }`}
              title="Inspect X.509 PKI Public Key Certificate"
            >
              <div className="flex items-center gap-2">
                <Lock className={`w-3.5 h-3.5 ${theme === 'light' ? 'text-[#059669]' : 'text-[#34D399]'}`} />
                <span className="font-medium">X.509 PKI Certificate</span>
              </div>
              <ChevronRight className="w-3 h-3 text-[#64748B]" />
            </button>
          )}

          {onOpenEmailAlert && (
            <button
              onClick={() => {
                onOpenEmailAlert();
                setMobileOpen(false);
              }}
              className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs transition cursor-pointer border ${
                theme === 'light'
                  ? 'border-[#CBD5E1] bg-white hover:bg-[#F1F5F9] text-[#0F172A]'
                  : 'border-[#1E293B] bg-[#131B2E] hover:bg-[#1E293B] text-[#E2E8F0]'
              }`}
              title="Open Executive Forensic Email Alert Modal"
            >
              <div className="flex items-center gap-2">
                <Mail className={`w-3.5 h-3.5 ${theme === 'light' ? 'text-[#DC2626]' : 'text-[#F87171]'}`} />
                <span className="font-medium">Executive Alert</span>
              </div>
              <ChevronRight className="w-3 h-3 text-[#64748B]" />
            </button>
          )}
        </div>
      </div>

      {/* Footer Info inside Sidebar */}
      <div className={`p-3.5 border-t text-[11px] font-mono ${
        theme === 'light' ? 'border-[#E2E8F0] bg-[#F8FAFC] text-[#64748B]' : 'border-[#1E293B] bg-[#090D16] text-[#64748B]'
      }`}>
        <div className="flex items-center gap-1.5 mb-1 text-[10px]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-pulse"></span>
          <span className={`font-semibold ${theme === 'light' ? 'text-[#059669]' : 'text-[#34D399]'}`}>
            Q-SHIELD Active
          </span>
        </div>
        <div className="truncate">Backend: Qiskit Aer</div>
        <div className="truncate">Digest: SHA-256</div>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Sidebar: Always 260px wide, fixed on left side of main content */}
      <aside className="hidden md:block w-[260px] min-w-[260px] shrink-0 min-h-[calc(100vh-140px)]">
        {sidebarContent}
      </aside>

      {/* Mobile Drawer Backdrop & Slide-out Menu */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
            onClick={() => setMobileOpen(false)}
            aria-hidden="true"
          />

          {/* Drawer Content */}
          <div className="relative z-50 w-[260px] max-w-[80vw] h-full shadow-2xl flex flex-col">
            {sidebarContent}
          </div>
        </div>
      )}
    </>
  );
}

export default LeftSidebar;
