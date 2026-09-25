import { useState, useMemo } from 'react';
import type { AnalysisResult, CertificateInfo } from '@/types';
import { Search, BadgeCheck, X, ShieldCheck, AlertTriangle, Clock, Key } from 'lucide-react';

interface CertificatesPageProps {
  result: AnalysisResult;
}

export function CertificatesPage({ result }: CertificatesPageProps) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selected, setSelected] = useState<CertificateInfo | null>(null);

  const certs = useMemo(() => {
    return result.sessions
      .filter(s => s.certificate)
      .map(s => ({ cert: s.certificate!, session: s }))
      .filter(({ cert, session }) => {
        if (statusFilter !== 'all' && cert.status !== statusFilter) return false;
        if (search) {
          const q = search.toLowerCase();
          return cert.subject.toLowerCase().includes(q) || cert.issuer.toLowerCase().includes(q) ||
            session.destinationIp.includes(q) || session.protocol.toLowerCase().includes(q);
        }
        return true;
      });
  }, [result.sessions, search, statusFilter]);

  const statusCounts = useMemo(() => {
    const counts = new Map<string, number>();
    result.sessions.forEach(s => {
      if (s.certificate) counts.set(s.certificate.status, (counts.get(s.certificate.status) || 0) + 1);
    });
    return Array.from(counts.entries());
  }, [result.sessions]);

  return (
    <div className="animate-fade-in">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-slate-100">Certificate Analysis</h2>
        <p className="text-sm text-slate-500 mt-1">X.509 certificates extracted from TLS sessions</p>
      </div>

      {/* Status summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
        {statusCounts.map(([status, count]) => (
          <div key={status} className="soc-card p-3 text-center">
            <div className={`text-2xl font-bold ${certColor(status)}`}>{count}</div>
            <div className="text-xs text-slate-500 capitalize mt-1">{status.replace('-', ' ')}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="soc-card p-4 mb-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search by subject, issuer, or host..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="soc-input w-full pl-9"
          />
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="soc-input">
          <option value="all">All Statuses</option>
          <option value="valid">Valid</option>
          <option value="expired">Expired</option>
          <option value="not-yet-valid">Not Yet Valid</option>
          <option value="weak-signature">Weak Signature</option>
          <option value="weak-key">Weak Key</option>
          <option value="hostname-mismatch">Hostname Mismatch</option>
          <option value="insufficient-data">Insufficient Data</option>
        </select>
      </div>

      {/* Certificate cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {certs.map(({ cert, session }, i) => (
          <div
            key={i}
            onClick={() => setSelected(cert)}
            className="soc-card soc-card-hover p-4 cursor-pointer border-l-4"
            style={{ borderLeftColor: certBorderColor(cert.status) }}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${certBgColor(cert.status)}`}>
                  <BadgeCheck className={`w-5 h-5 ${certColor(cert.status)}`} />
                </div>
                <div>
                  <p className="text-sm font-semibold text-slate-200 truncate max-w-[240px]">{cert.subject}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{session.protocol} · {session.destinationIp}</p>
                </div>
              </div>
              <span className={`text-xs font-semibold capitalize ${certColor(cert.status)}`}>{cert.status.replace('-', ' ')}</span>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-slate-500">Issuer: </span>
                <span className="text-slate-400">{cert.issuer}</span>
              </div>
              <div>
                <span className="text-slate-500">Key: </span>
                <span className="text-slate-400">{cert.publicKeyAlgorithm} {cert.publicKeySize > 0 ? `${cert.publicKeySize}b` : ''}</span>
              </div>
              <div>
                <span className="text-slate-500">Sig: </span>
                <span className="text-slate-400">{cert.signatureAlgorithm}</span>
              </div>
              <div>
                <span className="text-slate-500">Self-signed: </span>
                <span className={cert.selfSigned ? 'text-amber-400' : 'text-emerald-400'}>{cert.selfSigned ? 'Yes' : 'No'}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {certs.length === 0 && (
        <div className="soc-card py-12 text-center text-slate-500 text-sm">No certificates match the current filters.</div>
      )}

      {/* Detail modal */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={() => setSelected(null)}>
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl max-h-[85vh] overflow-y-auto scrollbar-thin animate-fade-in" onClick={e => e.stopPropagation()}>
            <div className="sticky top-0 bg-slate-900 border-b border-slate-800 px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <BadgeCheck className={`w-6 h-6 ${certColor(selected.status)}`} />
                <h3 className="text-lg font-bold text-slate-100">Certificate Details</h3>
              </div>
              <button onClick={() => setSelected(null)} className="text-slate-500 hover:text-slate-300">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className={`p-4 rounded-lg flex items-start gap-3 ${certBgColor(selected.status)}`}>
                {selected.status === 'valid' ? <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" /> : <AlertTriangle className={`w-5 h-5 ${certColor(selected.status)} shrink-0`} />}
                <div>
                  <p className={`font-semibold capitalize ${certColor(selected.status)}`}>{selected.status.replace('-', ' ')}</p>
                  <p className="text-sm text-slate-400 mt-1">{selected.statusDetail}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <CertField label="Subject" value={selected.subject} />
                <CertField label="Issuer" value={selected.issuer} />
                <CertField label="Serial Number" value={selected.serialNumber} mono />
                <CertField label="Signature Algorithm" value={selected.signatureAlgorithm} />
                <CertField label="Public Key Algorithm" value={selected.publicKeyAlgorithm} />
                <CertField label="Public Key Size" value={selected.publicKeySize > 0 ? `${selected.publicKeySize} bits` : 'Unknown'} />
                <CertField label="Valid From" value={selected.validFrom} icon={Clock} />
                <CertField label="Valid Until" value={selected.validUntil} icon={Clock} />
                <CertField label="Chain Depth" value={selected.chainDepth !== null ? String(selected.chainDepth) : 'Unknown'} icon={Key} />
                <CertField label="Self-Signed" value={selected.selfSigned ? 'Yes' : 'No'} />
              </div>

              {selected.sanEntries.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">SAN Entries</p>
                  <div className="flex flex-wrap gap-2">
                    {selected.sanEntries.map((san, i) => (
                      <span key={i} className="text-xs px-2 py-1 rounded bg-slate-800 text-slate-400 font-mono">{san}</span>
                    ))}
                  </div>
                </div>
              )}

              {selected.status === 'insufficient-data' && (
                <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                  <p className="text-xs text-slate-500">
                    Certificate details could not be fully extracted from the PCAP. The TLS handshake was observed, but the certificate data was not available in the capture. This is a known limitation of passive PCAP analysis.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function CertField({ label, value, mono, icon: Icon }: { label: string; value: string; mono?: boolean; icon?: typeof Clock }) {
  return (
    <div>
      <p className="text-xs text-slate-500 uppercase tracking-wide flex items-center gap-1">
        {Icon && <Icon className="w-3 h-3" />}{label}
      </p>
      <p className={`text-sm text-slate-200 mt-0.5 ${mono ? 'font-mono' : ''}`}>{value}</p>
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

function certBgColor(status: string): string {
  const colors: Record<string, string> = {
    valid: 'bg-emerald-500/10', expired: 'bg-red-500/10', 'not-yet-valid': 'bg-orange-500/10',
    'weak-signature': 'bg-amber-500/10', 'weak-key': 'bg-amber-500/10',
    'hostname-mismatch': 'bg-red-500/10', 'insufficient-data': 'bg-slate-500/10',
  };
  return colors[status] || 'bg-slate-500/10';
}

function certBorderColor(status: string): string {
  const colors: Record<string, string> = {
    valid: '#34d399', expired: '#f87171', 'not-yet-valid': '#fb923c',
    'weak-signature': '#fbbf24', 'weak-key': '#fbbf24',
    'hostname-mismatch': '#f87171', 'insufficient-data': '#64748b',
  };
  return colors[status] || '#94a3b8';
}
