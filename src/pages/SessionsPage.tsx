import { useState, useMemo } from 'react';
import type { AnalysisResult, EmailSession } from '@/types';
import { SeverityBadge, ConfidenceBadge } from '@/components/Badges';
import { Search, ChevronUp, ChevronDown, X, Lock, Unlock, ArrowRight } from 'lucide-react';

interface SessionsPageProps {
  result: AnalysisResult;
}

type SortField = 'timestamp' | 'protocol' | 'sourceIp' | 'destinationIp' | 'destinationPort' | 'riskScore';
type SortDir = 'asc' | 'desc';

export function SessionsPage({ result }: SessionsPageProps) {
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [tlsFilter, setTlsFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('riskScore');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [selectedSession, setSelectedSession] = useState<EmailSession | null>(null);

  const filtered = useMemo(() => {
    let list = result.sessions.filter(s => {
      if (protocolFilter !== 'all' && s.protocol !== protocolFilter) return false;
      if (riskFilter !== 'all' && s.riskLevel !== riskFilter) return false;
      if (tlsFilter === 'tls' && !s.hasTls) return false;
      if (tlsFilter === 'notls' && s.hasTls) return false;
      if (search) {
        const q = search.toLowerCase();
        return s.sourceIp.includes(q) || s.destinationIp.includes(q) ||
          s.protocol.toLowerCase().includes(q) || s.id.toLowerCase().includes(q);
      }
      return true;
    });

    list = list.sort((a, b) => {
      const dir = sortDir === 'asc' ? 1 : -1;
      const av = a[sortField];
      const bv = b[sortField];
      if (typeof av === 'string' && typeof bv === 'string') return av.localeCompare(bv) * dir;
      return ((av as number) - (bv as number)) * dir;
    });

    return list;
  }, [result.sessions, search, protocolFilter, riskFilter, tlsFilter, sortField, sortDir]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDir('desc'); }
  };

  const sortIcon = (field: SortField) => {
    if (sortField !== field) return null;
    return sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />;
  };

  const sessionFindings = selectedSession
    ? result.findings.filter(f => f.sessionId === selectedSession.id)
    : [];

  return (
    <div className="animate-fade-in">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-slate-100">PCAP Session Explorer</h2>
        <p className="text-sm text-slate-500 mt-1">{result.sessions.length} email sessions detected — click a row for details</p>
      </div>

      {/* Filters */}
      <div className="soc-card responsive-filters p-4 mb-4 grid gap-3 sm:grid-cols-2 xl:flex xl:items-center">
        <div className="relative min-w-0 sm:col-span-2 xl:flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search by IP, protocol, or session ID..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="soc-input w-full pl-9"
          />
        </div>
        <select value={protocolFilter} onChange={e => setProtocolFilter(e.target.value)} className="soc-input">
          <option value="all">All Protocols</option>
          <option value="SMTP">SMTP</option>
          <option value="IMAP">IMAP</option>
          <option value="POP3">POP3</option>
        </select>
        <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)} className="soc-input">
          <option value="all">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
        <select value={tlsFilter} onChange={e => setTlsFilter(e.target.value)} className="soc-input">
          <option value="all">All Sessions</option>
          <option value="tls">TLS Only</option>
          <option value="notls">No TLS</option>
        </select>
      </div>

      {/* Table */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto scrollbar-thin">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-xs uppercase tracking-wide">
                <th className="px-4 py-3 text-left cursor-pointer hover:text-slate-300" onClick={() => toggleSort('timestamp')}>Timestamp {sortIcon('timestamp')}</th>
                <th className="px-4 py-3 text-left cursor-pointer hover:text-slate-300" onClick={() => toggleSort('protocol')}>Protocol {sortIcon('protocol')}</th>
                <th className="px-4 py-3 text-left cursor-pointer hover:text-slate-300" onClick={() => toggleSort('sourceIp')}>Source {sortIcon('sourceIp')}</th>
                <th className="px-4 py-3 text-left cursor-pointer hover:text-slate-300" onClick={() => toggleSort('destinationIp')}>Destination {sortIcon('destinationIp')}</th>
                <th className="px-4 py-3 text-left cursor-pointer hover:text-slate-300" onClick={() => toggleSort('destinationPort')}>Port {sortIcon('destinationPort')}</th>
                <th className="px-4 py-3 text-center">TLS</th>
                <th className="px-4 py-3 text-left">TLS Version</th>
                <th className="px-4 py-3 text-left">Cipher</th>
                <th className="px-4 py-3 text-left">Cert Status</th>
                <th className="px-4 py-3 text-left cursor-pointer hover:text-slate-300" onClick={() => toggleSort('riskScore')}>Risk {sortIcon('riskScore')}</th>
                <th className="px-4 py-3 text-center">Conf.</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(s => (
                <tr
                  key={s.id}
                  onClick={() => setSelectedSession(s)}
                  className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{new Date(s.timestamp).toLocaleTimeString()}</td>
                  <td className="px-4 py-3"><span className="text-sky-400 font-medium">{s.protocol}</span></td>
                  <td className="px-4 py-3 text-slate-300 font-mono text-xs">{s.sourceIp}:{s.sourcePort}</td>
                  <td className="px-4 py-3 text-slate-300 font-mono text-xs">{s.destinationIp}:{s.destinationPort}</td>
                  <td className="px-4 py-3 text-slate-400">{s.destinationPort}</td>
                  <td className="px-4 py-3 text-center">
                    {s.hasTls ? <Lock className="w-4 h-4 text-emerald-400 mx-auto" /> : <Unlock className="w-4 h-4 text-red-400 mx-auto" />}
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs">{s.tls?.version || '—'}</td>
                  <td className="px-4 py-3 text-slate-500 text-xs max-w-[180px] truncate" title={s.tls?.cipherSuite || ''}>{s.tls?.cipherSuite?.split('_').slice(-2).join('_') || '—'}</td>
                  <td className="px-4 py-3 text-xs">
                    {s.certificate ? (
                      <span className={certColor(s.certificate.status)}>{s.certificate.status}</span>
                    ) : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className={`w-12 h-1.5 rounded-full ${riskBarColor(s.riskLevel)}`}>
                        <div className={`h-full rounded-full ${riskBarFill(s.riskLevel)}`} style={{ width: `${s.riskScore}%` }} />
                      </div>
                      <span className={`text-xs font-semibold ${riskTextColor(s.riskLevel)}`}>{s.riskScore}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-center"><ConfidenceBadge confidence={s.confidence} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <div className="py-12 text-center text-slate-500 text-sm">No sessions match the current filters.</div>
        )}
      </div>

      {/* Session detail drawer */}
      {selectedSession && (
        <div className="fixed inset-0 z-50 flex justify-end" onClick={() => setSelectedSession(null)}>
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />
          <div
            className="relative mt-16 w-full bg-slate-900 border-l border-slate-800 overflow-y-auto scrollbar-thin animate-fade-in sm:mt-0 sm:max-w-lg"
            onClick={e => e.stopPropagation()}
          >
            <div className="sticky top-0 bg-slate-900 border-b border-slate-800 px-6 py-4 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold text-slate-100">Session {selectedSession.id}</h3>
                <p className="text-xs text-slate-500">{new Date(selectedSession.timestamp).toLocaleString()}</p>
              </div>
              <button onClick={() => setSelectedSession(null)} className="text-slate-500 hover:text-slate-300">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <DetailItem label="Protocol" value={selectedSession.protocol} />
                <DetailItem label="Duration" value={`${selectedSession.sessionDuration}s`} />
                <DetailItem label="Source" value={`${selectedSession.sourceIp}:${selectedSession.sourcePort}`} mono />
                <DetailItem label="Destination" value={`${selectedSession.destinationIp}:${selectedSession.destinationPort}`} mono />
                <DetailItem label="Packets" value={String(selectedSession.packetCount)} />
                <DetailItem label="Risk Score" value={`${selectedSession.riskScore}/100`} />
              </div>

              <div className="flex items-center gap-3">
                <SeverityBadge severity={selectedSession.riskLevel} />
                <ConfidenceBadge confidence={selectedSession.confidence} />
                {selectedSession.hasTls ? (
                  <span className="soc-badge severity-low"><Lock className="w-3 h-3" /> TLS</span>
                ) : (
                  <span className="soc-badge severity-critical"><Unlock className="w-3 h-3" /> No TLS</span>
                )}
                {selectedSession.isStartTls && <span className="soc-badge severity-informational">STARTTLS</span>}
              </div>

              <div className="border-t border-slate-800 pt-4">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">STARTTLS Status</h4>
                <p className="text-sm text-slate-400 capitalize">{selectedSession.startTlsStatus.replace('-', ' ')}</p>
              </div>

              {selectedSession.tls && (
                <div className="border-t border-slate-800 pt-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">TLS Information</h4>
                  <div className="grid grid-cols-2 gap-3">
                    <DetailItem label="Version" value={selectedSession.tls.version} />
                    <DetailItem label="Cipher Suite" value={selectedSession.tls.cipherSuite} mono small />
                    <DetailItem label="Key Exchange" value={selectedSession.tls.keyExchange || '—'} />
                    <DetailItem label="Encryption" value={selectedSession.tls.encryption || '—'} />
                    <DetailItem label="Authentication" value={selectedSession.tls.authentication || '—'} />
                    <DetailItem label="MAC" value={selectedSession.tls.mac || '—'} />
                    <DetailItem label="Forward Secrecy" value={selectedSession.tls.forwardSecrecy === true ? 'Yes' : selectedSession.tls.forwardSecrecy === false ? 'No' : 'Unknown'} />
                  </div>
                </div>
              )}

              {selectedSession.certificate && (
                <div className="border-t border-slate-800 pt-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Certificate</h4>
                  <div className="grid grid-cols-2 gap-3">
                    <DetailItem label="Subject" value={selectedSession.certificate.subject} small />
                    <DetailItem label="Issuer" value={selectedSession.certificate.issuer} small />
                    <DetailItem label="Status" value={selectedSession.certificate.status} />
                    <DetailItem label="Self-Signed" value={selectedSession.certificate.selfSigned ? 'Yes' : 'No'} />
                    <DetailItem label="Signature Algo" value={selectedSession.certificate.signatureAlgorithm} small />
                    <DetailItem label="Key" value={`${selectedSession.certificate.publicKeyAlgorithm} ${selectedSession.certificate.publicKeySize}b`} />
                  </div>
                  <p className="text-xs text-slate-500 mt-2">{selectedSession.certificate.statusDetail}</p>
                </div>
              )}

              {sessionFindings.length > 0 && (
                <div className="border-t border-slate-800 pt-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Findings ({sessionFindings.length})</h4>
                  <div className="space-y-2">
                    {sessionFindings.map(f => (
                      <div key={f.id} className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                        <div className="flex items-center gap-2 mb-1">
                          <SeverityBadge severity={f.severity} />
                          <span className="text-xs text-slate-500">{f.category}</span>
                        </div>
                        <p className="text-sm text-slate-300">{f.title}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailItem({ label, value, mono, small }: { label: string; value: string; mono?: boolean; small?: boolean }) {
  return (
    <div>
      <p className="text-xs text-slate-500 uppercase tracking-wide">{label}</p>
      <p className={`text-slate-200 ${mono ? 'font-mono' : ''} ${small ? 'text-xs' : 'text-sm'}`}>{value}</p>
    </div>
  );
}

function certColor(status: string): string {
  const colors: Record<string, string> = {
    valid: 'text-emerald-400', expired: 'text-red-400', 'not-yet-valid': 'text-orange-400',
    'weak-signature': 'text-amber-400', 'weak-key': 'text-amber-400',
    'hostname-mismatch': 'text-red-400', 'insufficient-data': 'text-slate-500',
  };
  return colors[status] || 'text-slate-400';
}

function riskBarColor(level: string): string {
  return 'bg-slate-800';
}

function riskBarFill(level: string): string {
  const colors: Record<string, string> = {
    critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-emerald-500', informational: 'bg-sky-500',
  };
  return colors[level] || 'bg-slate-500';
}

function riskTextColor(level: string): string {
  const colors: Record<string, string> = {
    critical: 'text-red-400', high: 'text-orange-400', medium: 'text-amber-400', low: 'text-emerald-400', informational: 'text-sky-400',
  };
  return colors[level] || 'text-slate-400';
}
