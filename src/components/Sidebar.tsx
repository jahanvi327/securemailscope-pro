import { useEffect, useState } from 'react';
import { Shield, Upload, LayoutDashboard, Table, AlertTriangle, BadgeCheck, Lock, FileText, Settings, Menu, X, Moon, Sun } from 'lucide-react';
import { Button } from '@/components/ui/button';

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
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => setMenuOpen(false), [currentPage]);

  useEffect(() => {
    const savedTheme = window.localStorage.getItem('secure-mail-scope-theme');
    const nextTheme = savedTheme === 'light' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.classList.toggle('light', nextTheme === 'light');
    document.documentElement.classList.toggle('dark', nextTheme === 'dark');
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    window.localStorage.setItem('secure-mail-scope-theme', nextTheme);
    document.documentElement.classList.toggle('light', nextTheme === 'light');
    document.documentElement.classList.toggle('dark', nextTheme === 'dark');
  };

  const themeToggle = (className = '') => (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      onClick={toggleTheme}
      className={`theme-toggle shrink-0 rounded-xl border border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-slate-100 ${className}`}
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
    >
      <span className="theme-toggle-icon" aria-hidden="true">
        {theme === 'dark' ? <Sun /> : <Moon />}
      </span>
    </Button>
  );

  const navigate = (page: PageId, disabled: boolean) => {
    if (!disabled) onNavigate(page);
  };

  const nav = (mobile = false) => (
    <nav className={mobile ? 'grid grid-cols-2 gap-2 p-4' : 'flex-1 px-3 py-4 space-y-1 overflow-y-auto scrollbar-thin'}>
      {navItems.map(item => {
        const Icon = item.icon;
        const active = currentPage === item.id;
        const disabled = !hasAnalysis && item.id !== 'upload' && item.id !== 'settings' && item.id !== 'dashboard';
        return (
          <button
            key={item.id}
            onClick={() => navigate(item.id, disabled)}
            disabled={disabled}
            aria-current={active ? 'page' : undefined}
            className={`nav-item min-h-11 w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
              active
                ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20'
                : disabled
                ? 'text-slate-600 cursor-not-allowed'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Icon className="w-4 h-4 shrink-0" />
            <span className="truncate">{item.label}</span>
          </button>
        );
      })}
    </nav>
  );

  return (
    <>
      <header className="mobile-header fixed inset-x-0 top-0 z-40 hidden h-16 items-center justify-between border-b border-slate-800/70 bg-slate-950/85 px-4 backdrop-blur-xl">
        <button onClick={() => onNavigate('dashboard')} className="flex min-w-0 items-center gap-2.5 text-left" aria-label="Open dashboard">
          <div className="brand-mark grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-sky-500 to-cyan-600 shadow-lg shadow-sky-500/20" aria-hidden="true">
            <span className="brand-letter">M</span>
          </div>
          <div className="min-w-0">
            <p className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-[0.2em] text-cyan-400"><span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />Live Interface</p>
            <h1 className="truncate text-sm font-bold text-slate-100">SecureMailScope</h1>
          </div>
        </button>
        <div className="flex items-center gap-2">
          {themeToggle('h-11 w-11')}
          <Button type="button" variant="ghost" size="icon" onClick={() => setMenuOpen(value => !value)} className="h-11 w-11 rounded-xl border border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-slate-100" aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={menuOpen}>
            {menuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
        </div>
      </header>

      {menuOpen && (
        <div className="mobile-menu fixed inset-0 z-30 hidden bg-slate-950/70 pt-16 backdrop-blur-md" onClick={() => setMenuOpen(false)}>
          <div className="mx-3 mt-3 rounded-2xl border border-slate-800 bg-slate-900/95 shadow-2xl" onClick={event => event.stopPropagation()}>
            {nav(true)}
            <div className="flex items-center gap-2 border-t border-slate-800 px-4 py-3 text-xs text-slate-500"><Shield className="h-3.5 w-3.5" />Defensive Analysis Only</div>
          </div>
        </div>
      )}

      <aside className="desktop-sidebar w-60 shrink-0 bg-slate-900/60 border-r border-slate-800 flex flex-col h-screen sticky top-0">
      <div className="px-5 py-5 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="brand-mark w-9 h-9 rounded-lg bg-gradient-to-br from-sky-500 to-cyan-600 flex items-center justify-center shadow-lg shadow-sky-500/20" aria-hidden="true">
            <span className="brand-letter">M</span>
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-100 tracking-tight">SecureMailScope</h1>
            <p className="text-[10px] text-slate-500 tracking-wide">SECURITY POSTURE ASSESSMENT</p>
          </div>
        </div>
      </div>

      {nav()}

      <div className="px-4 py-3 border-t border-slate-800">
        <div className="mb-3 flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/50 p-2 pl-3">
          <span className="text-xs font-medium text-slate-400">{theme === 'dark' ? 'Dark mode' : 'Light mode'}</span>
          {themeToggle()}
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <Shield className="w-3.5 h-3.5" />
          <span>Defensive Analysis Only</span>
        </div>
      </div>
      </aside>
    </>
  );
}
