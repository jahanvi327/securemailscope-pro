import type { AnalysisResult } from '@/types';
import { ScoreGauge, SeverityBadge } from '@/components/Badges';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, RadialBarChart, RadialBar,
} from 'recharts';
import { Shield, Activity, Lock, AlertTriangle, Server, Mail, TrendingUp } from 'lucide-react';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#34d399', informational: '#60a5fa',
};

const TLS_COLORS = ['#60a5fa', '#34d399', '#fbbf24', '#fb923c', '#f87171', '#94a3b8'];

interface DashboardProps {
  result: AnalysisResult;
}

export function Dashboard({ result }: DashboardProps) {
  const s = result.score;
  const smtpCount = result.sessions.filter(x => x.protocol === 'SMTP').length;
  const imapCount = result.sessions.filter(x => x.protocol === 'IMAP').length;
  const pop3Count = result.sessions.filter(x => x.protocol === 'POP3').length;
  const tlsCount = result.sessions.filter(x => x.hasTls).length;

  const severityData = [
    { name: 'Critical', value: s.criticalCount, color: SEVERITY_COLORS.critical },
    { name: 'High', value: s.highCount, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: s.mediumCount, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: s.lowCount, color: SEVERITY_COLORS.low },
    { name: 'Info', value: s.informationalCount, color: SEVERITY_COLORS.informational },
  ].filter(d => d.value > 0);

  const protocolData = result.findingsByProtocol.map(p => ({ name: p.protocol, count: p.count }));
  const tlsData = result.tlsVersionDistribution.map((t, i) => ({ name: t.version, value: t.count, percentage: t.percentage, color: TLS_COLORS[i % TLS_COLORS.length] }));
  const cipherData = result.cipherDistribution.map(c => ({ name: c.cipher.split('_').slice(-2).join('_'), full: c.cipher, count: c.count }));
  const certData = result.certificateStatusDistribution.map(c => ({ name: c.status, count: c.count }));

  const scoreBreakdownData = [
    { name: 'TLS Config', value: s.breakdown.tlsConfiguration, fill: '#60a5fa' },
    { name: 'Cert Security', value: s.breakdown.certificateSecurity, fill: '#34d399' },
    { name: 'Protocol', value: s.breakdown.protocolSecurity, fill: '#fbbf24' },
    { name: 'Encryption', value: s.breakdown.encryptionCoverage, fill: '#0ea5e9' },
    { name: 'Crypto Strength', value: s.breakdown.cryptographicStrength, fill: '#8b5cf6' },
    { name: 'Weaknesses', value: s.breakdown.configurationWeaknesses, fill: '#fb923c' },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-4 sm:flex sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-2xl font-bold text-slate-100">Security Dashboard</h2>
          <p className="text-sm text-slate-500 mt-1">
            {result.isDemo ? 'Synthetic demo dataset' : `Analysis of ${result.fileName}`} — {new Date(result.uploadedAt).toLocaleString()}
          </p>
        </div>
        {result.isDemo && (
          <span className="soc-badge shrink-0 severity-medium">SYNTHETIC DEMO DATA</span>
        )}
      </div>

      {/* Top stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Shield} label="Security Score" value={`${s.overall}/100`} subtext={s.riskLevel.toUpperCase()} color={s.overall >= 80 ? 'text-emerald-400' : s.overall >= 60 ? 'text-amber-400' : s.overall >= 40 ? 'text-orange-400' : 'text-red-400'} />
        <StatCard icon={Activity} label="Total Sessions" value={String(result.sessions.length)} subtext={`${tlsCount} with TLS`} color="text-sky-400" />
        <StatCard icon={AlertTriangle} label="Total Findings" value={String(s.totalFindings)} subtext={`${s.criticalCount} critical, ${s.highCount} high`} color="text-amber-400" />
        <StatCard icon={Lock} label="TLS Coverage" value={`${Math.round((tlsCount / Math.max(result.sessions.length, 1)) * 100)}%`} subtext={`${result.tlsVersionDistribution.length} TLS versions`} color="text-cyan-400" />
      </div>

      {/* Score + Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="soc-card p-6 flex flex-col items-center justify-center">
          <h3 className="text-sm font-semibold text-slate-400 mb-4 self-start">Overall Security Score</h3>
          <ScoreGauge score={s.overall} />
          <div className="mt-4 grid grid-cols-2 gap-2 w-full">
            <MiniStat label="Critical" value={s.criticalCount} color="text-red-400" />
            <MiniStat label="High" value={s.highCount} color="text-orange-400" />
            <MiniStat label="Medium" value={s.mediumCount} color="text-amber-400" />
            <MiniStat label="Low" value={s.lowCount} color="text-emerald-400" />
          </div>
        </div>

        <div className="soc-card p-6 lg:col-span-2">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">Score Breakdown</h3>
          <ResponsiveContainer width="100%" height={220}>
            <RadialBarChart data={scoreBreakdownData} innerRadius="20%" outerRadius="100%" startAngle={90} endAngle={-270}>
              <RadialBar dataKey="value" cornerRadius={6} background={{ fill: '#1e293b' }} />
              <Legend iconType="circle" layout="vertical" verticalAlign="middle" align="right" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-3 gap-2 mt-2">
            {scoreBreakdownData.map(d => (
              <div key={d.name} className="text-center">
                <div className="text-xs text-slate-500">{d.name}</div>
                <div className="text-sm font-semibold" style={{ color: d.fill }}>{d.value}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Protocol stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <ProtocolCard icon={Mail} label="SMTP" count={smtpCount} color="text-sky-400" bg="bg-sky-500/10" />
        <ProtocolCard icon={Mail} label="IMAP" count={imapCount} color="text-cyan-400" bg="bg-cyan-500/10" />
        <ProtocolCard icon={Mail} label="POP3" count={pop3Count} color="text-teal-400" bg="bg-teal-500/10" />
        <ProtocolCard icon={Lock} label="TLS Sessions" count={tlsCount} color="text-emerald-400" bg="bg-emerald-500/10" />
      </div>

      {/* Charts grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Findings by severity */}
        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">Findings by Severity</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={50} paddingAngle={3}>
                  {severityData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <EmptyChart text="No findings detected" />}
        </div>

        {/* Findings by protocol */}
        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">Findings by Protocol</h3>
          {protocolData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={protocolData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                <Bar dataKey="count" fill="#38bdf8" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyChart text="No findings detected" />}
        </div>

        {/* TLS version distribution */}
        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">TLS Version Distribution</h3>
          {tlsData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={tlsData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} innerRadius={50} paddingAngle={3}>
                  {tlsData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <EmptyChart text="No TLS sessions detected" />}
        </div>

        {/* Cipher suite distribution */}
        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">Cipher Suite Distribution</h3>
          {cipherData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={cipherData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
                <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={9} width={120} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} formatter={(v) => [`${v} sessions`, 'Count']} />
                <Bar dataKey="count" fill="#0ea5e9" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyChart text="No cipher suites detected" />}
        </div>
      </div>

      {/* Certificate status + Top risky hosts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">Certificate Status</h3>
          {certData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={certData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} angle={-15} textAnchor="end" height={60} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyChart text="No certificates detected" />}
        </div>

        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">Top Risky Hosts</h3>
          {result.topRiskyHosts.length > 0 ? (
            <div className="space-y-2">
              {result.topRiskyHosts.slice(0, 6).map((host, i) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold ${host.riskScore < 40 ? 'bg-red-500/10 text-red-400' : host.riskScore < 60 ? 'bg-orange-500/10 text-orange-400' : host.riskScore < 80 ? 'bg-amber-500/10 text-amber-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
                      <Server className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-slate-200">{host.host}</div>
                      <div className="text-xs text-slate-500">{host.findingCount} findings</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <TrendingUp className={`w-4 h-4 ${host.riskScore < 50 ? 'text-red-400' : 'text-amber-400'}`} />
                    <span className={`text-sm font-bold ${host.riskScore < 40 ? 'text-red-400' : host.riskScore < 60 ? 'text-orange-400' : host.riskScore < 80 ? 'text-amber-400' : 'text-emerald-400'}`}>{host.riskScore}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : <EmptyChart text="No risky hosts detected" />}
        </div>
      </div>

      {/* Top finding */}
      {result.findings.length > 0 && (
        <div className="soc-card p-6">
          <h3 className="text-sm font-semibold text-slate-400 mb-4">Top Priority Finding (AI-Ranked)</h3>
          <div className="p-4 rounded-lg bg-slate-800/50 border-l-4" style={{ borderColor: SEVERITY_COLORS[result.findings[0].severity] }}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <SeverityBadge severity={result.findings[0].severity} />
                  <span className="text-xs text-slate-500">{result.findings[0].category}</span>
                </div>
                <h4 className="text-lg font-semibold text-slate-100">{result.findings[0].title}</h4>
                <p className="text-sm text-slate-400 mt-1">{result.findings[0].evidence}</p>
                <p className="text-xs text-slate-500 mt-2 italic">{result.findings[0].aiExplanation}</p>
              </div>
              <div className="text-right shrink-0">
                <div className="text-2xl font-bold text-sky-400">{result.findings[0].aiPriority}</div>
                <div className="text-xs text-slate-500">AI Priority</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ icon: Icon, label, value, subtext, color }: { icon: typeof Shield; label: string; value: string; subtext: string; color: string }) {
  return (
    <div className="soc-card soc-card-hover p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wide">{label}</p>
          <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
          <p className="text-xs text-slate-500 mt-1">{subtext}</p>
        </div>
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color.replace('text-', 'bg-').replace('-400', '-500/10')}`}>
          <Icon className={`w-5 h-5 ${color}`} />
        </div>
      </div>
    </div>
  );
}

function ProtocolCard({ icon: Icon, label, count, color, bg }: { icon: typeof Mail; label: string; count: number; color: string; bg: string }) {
  return (
    <div className="soc-card soc-card-hover p-4 flex items-center gap-3">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${bg}`}>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        <p className={`text-xl font-bold ${color}`}>{count}</p>
      </div>
    </div>
  );
}

function MiniStat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center p-2 rounded-lg bg-slate-800/50">
      <div className={`text-lg font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}

function EmptyChart({ text }: { text: string }) {
  return (
    <div className="h-[250px] flex items-center justify-center text-slate-600 text-sm">{text}</div>
  );
}
