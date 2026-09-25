import { useState, useMemo } from 'react';
import type { AnalysisResult, TlsVersion } from '@/types';
import { Lock, Unlock, ShieldCheck, AlertTriangle, Search } from 'lucide-react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

interface TlsPageProps {
  result: AnalysisResult;
}

const TLS_COLORS: Record<string, string> = {
  'TLS 1.3': '#34d399', 'TLS 1.2': '#60a5fa', 'TLS 1.1': '#fbbf24', 'TLS 1.0': '#fb923c', 'Unknown': '#f87171',
};

export function TlsPage({ result }: TlsPageProps) {
  const [search, setSearch] = useState('');
  const [versionFilter, setVersionFilter] = useState<string>('all');

  const tlsSessions = useMemo(() => {
    return result.sessions.filter(s => {
      if (!s.hasTls || !s.tls) return false;
      if (versionFilter !== 'all' && s.tls.version !== versionFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return s.sourceIp.includes(q) || s.destinationIp.includes(q) ||
          s.tls.cipherSuite.toLowerCase().includes(q) || s.protocol.toLowerCase().includes(q);
      }
      return true;
    });
  }, [result.sessions, search, versionFilter]);

  const tlsVersionData = result.tlsVersionDistribution.map(t => ({
    name: t.version, value: t.count, percentage: t.percentage, color: TLS_COLORS[t.version] || '#94a3b8',
  }));

  const cipherData = useMemo(() => {
    const counts = new Map<string, number>();
    result.sessions.forEach(s => {
      if (s.tls) counts.set(s.tls.cipherSuite, (counts.get(s.tls.cipherSuite) || 0) + 1);
    });
    return Array.from(counts.entries()).map(([cipher, count]) => ({
      name: cipher.split('_').slice(-2).join('_'),
      full: cipher,
      count,
    }));
  }, [result.sessions]);

  const fsData = useMemo(() => {
    const withFs = result.sessions.filter(s => s.tls?.forwardSecrecy === true).length;
    const withoutFs = result.sessions.filter(s => s.tls?.forwardSecrecy === false).length;
    const unknown = result.sessions.filter(s => s.tls?.forwardSecrecy === null).length;
    return [
      { name: 'Forward Secrecy', value: withFs, color: '#34d399' },
      { name: 'No Forward Secrecy', value: withoutFs, color: '#fb923c' },
      { name: 'Unknown', value: unknown, color: '#64748b' },
    ].filter(d => d.value > 0);
  }, [result.sessions]);

  const deprecatedCount = result.sessions.filter(s => s.tls && ['TLS 1.0', 'TLS 1.1'].includes(s.tls.version)).length;
  const secureCount = result.sessions.filter(s => s.tls && ['TLS 1.2', 'TLS 1.3'].includes(s.tls.version)).length;
  const plaintextCount = result.sessions.filter(s => !s.hasTls).length;

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="mb-2">
        <h2 className="text-2xl font-bold text-slate-100">TLS Analysis</h2>
        <p className="text-sm text-slate-500 mt-1">TLS versions, cipher suites, and encryption characteristics</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <TlsStatCard icon={ShieldCheck} label="Secure TLS" value={secureCount} color="text-emerald-400" bg="bg-emerald-500/10" />
        <TlsStatCard icon={AlertTriangle} label="Deprecated TLS" value={deprecatedCount} color="text-orange-400" bg="bg-orange-500/10" />
        <TlsStatCard icon={Unlock} label="Plaintext" value={plaintextCount} color="text-red-400" bg="bg-red-500/10" />
        <TlsStatCard icon={Lock} label="Total TLS" value={result.sessions.filter(s => s.hasTls).length} color="text-sky-400" bg="bg-sky-500/10" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">TLS Version Distribution</h3>
          {tlsVersionData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={tlsVersionData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={50} paddingAngle={3}>
                  {tlsVersionData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <div className="h-[250px] flex items-center justify-center text-slate-600 text-sm">No TLS sessions detected</div>}
        </div>

        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">Forward Secrecy</h3>
          {fsData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={fsData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={50} paddingAngle={3}>
                  {fsData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <div className="h-[250px] flex items-center justify-center text-slate-600 text-sm">No TLS sessions detected</div>}
        </div>
      </div>

      {/* Cipher suites */}
      <div className="soc-card p-6">
        <h3 className="text-sm font-semibold text-slate-400 mb-4">Cipher Suite Distribution</h3>
        {cipherData.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={cipherData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
              <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={9} width={160} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
              <Bar dataKey="count" fill="#0ea5e9" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : <div className="h-[300px] flex items-center justify-center text-slate-600 text-sm">No cipher suites detected</div>}
      </div>

      {/* Session table */}
      <div className="soc-card responsive-filters p-4 mb-4 grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
        <div className="relative min-w-0">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search TLS sessions..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="soc-input w-full pl-9"
          />
        </div>
        <select value={versionFilter} onChange={e => setVersionFilter(e.target.value)} className="soc-input">
          <option value="all">All TLS Versions</option>
          <option value="TLS 1.3">TLS 1.3</option>
          <option value="TLS 1.2">TLS 1.2</option>
          <option value="TLS 1.1">TLS 1.1</option>
          <option value="TLS 1.0">TLS 1.0</option>
        </select>
      </div>

      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto scrollbar-thin">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-xs uppercase tracking-wide">
                <th className="px-4 py-3 text-left">Session</th>
                <th className="px-4 py-3 text-left">Protocol</th>
                <th className="px-4 py-3 text-left">Source → Destination</th>
                <th className="px-4 py-3 text-left">TLS Version</th>
                <th className="px-4 py-3 text-left">Cipher Suite</th>
                <th className="px-4 py-3 text-left">Key Exchange</th>
                <th className="px-4 py-3 text-left">Encryption</th>
                <th className="px-4 py-3 text-center">Forward Secrecy</th>
              </tr>
            </thead>
            <tbody>
              {tlsSessions.map(s => (
                <tr key={s.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-4 py-3 text-slate-400">{s.id}</td>
                  <td className="px-4 py-3 text-sky-400 font-medium">{s.protocol}</td>
                  <td className="px-4 py-3 text-slate-300 font-mono text-xs">{s.sourceIp} → {s.destinationIp}</td>
                  <td className="px-4 py-3">
                    <span className="font-medium" style={{ color: TLS_COLORS[s.tls!.version] || '#94a3b8' }}>{s.tls!.version}</span>
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs max-w-[200px] truncate" title={s.tls!.cipherSuite}>{s.tls!.cipherSuite}</td>
                  <td className="px-4 py-3 text-slate-400 text-xs">{s.tls!.keyExchange || '—'}</td>
                  <td className="px-4 py-3 text-slate-400 text-xs">{s.tls!.encryption || '—'}</td>
                  <td className="px-4 py-3 text-center">
                    {s.tls!.forwardSecrecy === true ? <ShieldCheck className="w-4 h-4 text-emerald-400 mx-auto" /> :
                     s.tls!.forwardSecrecy === false ? <AlertTriangle className="w-4 h-4 text-orange-400 mx-auto" /> :
                     <span className="text-slate-600 text-xs">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {tlsSessions.length === 0 && (
          <div className="py-12 text-center text-slate-500 text-sm">No TLS sessions match the current filters.</div>
        )}
      </div>
    </div>
  );
}

function TlsStatCard({ icon: Icon, label, value, color, bg }: { icon: typeof Lock; label: string; value: number; color: string; bg: string }) {
  return (
    <div className="soc-card p-4 flex items-center gap-3">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${bg}`}>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        <p className={`text-xl font-bold ${color}`}>{value}</p>
      </div>
    </div>
  );
}
