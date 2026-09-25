import { Shield, Upload, LayoutDashboard, Table, AlertTriangle, BadgeCheck, Lock, FileText, Settings, Mail } from 'lucide-react';

export type PageId = 'dashboard' | 'upload' | 'sessions' | 'findings' | 'certificates' | 'tls' | 'reports' | 'settings';

interface NavItem {
  id: PageId;
  label: string;
  icon: typeof Shield;
}

const navItems: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'upload', label: 'Upload PCAP', icon: Upload },
  { id: 'sessions', label: 'Sessions', icon: Table },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'certificates', label: 'Certificates', icon: BadgeCheck },
  { id: 'tls', label: 'TLS Analysis', icon: Lock },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
];

interface SidebarProps {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
  hasAnalysis: boolean;
}

export function Sidebar({ currentPage, onNavigate, hasAnalysis }: SidebarProps) {
  return (
    <aside className="w-60 shrink-0 bg-slate-900/60 border-r border-slate-800 flex flex-col h-screen sticky top-0">
      <div className="px-5 py-5 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-sky-500 to-cyan-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
            <Mail className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 tracking-tight">SecureMailScope</h1>
            <p className="text-[10px] text-slate-500 tracking-wide">SECURITY POSTURE ASSESSMENT</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto scrollbar-thin">
        {navItems.map(item => {
          const Icon = item.icon;
          const active = currentPage === item.id;
          const disabled = !hasAnalysis && item.id !== 'upload' && item.id !== 'settings' && item.id !== 'dashboard';
          return (
            <button
              key={item.id}
              onClick={() => !disabled && onNavigate(item.id)}
              disabled={disabled}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                active
                  ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20'
                  : disabled
                  ? 'text-slate-600 cursor-not-allowed'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {item.label}
            </button>
          );
        })}
      </nav>

      <div className="px-4 py-3 border-t border-slate-800">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <Shield className="w-3.5 h-3.5" />
          <span>Defensive Analysis Only</span>
        </div>
      </div>
    </aside>
  );
}
