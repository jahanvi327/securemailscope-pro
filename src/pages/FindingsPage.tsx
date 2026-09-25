import { useState, useMemo } from 'react';
import type { AnalysisResult, SecurityFinding } from '@/types';
import { SeverityBadge, ConfidenceBadge } from '@/components/Badges';
import { Search, Filter, X, Brain, ChevronDown, ChevronRight, AlertTriangle } from 'lucide-react';

interface FindingsPageProps {
  result: AnalysisResult;
}

export function FindingsPage({ result }: FindingsPageProps) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const categories = useMemo(() => {
    const set = new Set(result.findings.map(f => f.category));
    return Array.from(set).sort();
  }, [result.findings]);

  const filtered = useMemo(() => {
    return result.findings.filter(f => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (categoryFilter !== 'all' && f.category !== categoryFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return f.title.toLowerCase().includes(q) || f.evidence.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q) || f.source.includes(q) || f.destination.includes(q);
      }
      return true;
    });
  }, [result.findings, search, severityFilter, categoryFilter]);

  return (
    <div className="animate-fade-in">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-slate-100">Security Findings</h2>
        <p className="text-sm text-slate-500 mt-1">{result.findings.length} findings — sorted by AI priority</p>
      </div>

      {/* AI notice */}
      <div className="soc-card p-4 mb-4 flex items-start gap-3">
        <Brain className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
        <div className="text-sm text-slate-400">
          <p className="text-slate-300 font-medium">AI-Assisted Prioritization</p>
          <p className="mt-1">Findings are ranked by an AI model that weighs severity, confidence, protocol, and category. AI explanations are based only on extracted packet features — the model never invents evidence.</p>
        </div>
      </div>

      {/* Filters */}
      <div className="soc-card p-4 mb-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search findings..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="soc-input w-full pl-9"
          />
        </div>
        <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} className="soc-input">
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
        <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)} className="soc-input">
          <option value="all">All Categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>

      {/* Findings list */}
      <div className="space-y-2">
        {filtered.map(f => (
          <FindingCard
            key={f.id}
            finding={f}
            expanded={expandedId === f.id}
            onToggle={() => setExpandedId(expandedId === f.id ? null : f.id)}
          />
        ))}
        {filtered.length === 0 && (
          <div className="soc-card py-12 text-center text-slate-500 text-sm flex flex-col items-center gap-2">
            <AlertTriangle className="w-8 h-8 text-slate-600" />
            No findings match the current filters.
          </div>
        )}
      </div>
    </div>
  );
}

function FindingCard({ finding, expanded, onToggle }: { finding: SecurityFinding; expanded: boolean; onToggle: () => void }) {
  const severityBorder: Record<string, string> = {
    critical: 'border-l-red-500', high: 'border-l-orange-500', medium: 'border-l-amber-500',
    low: 'border-l-emerald-500', informational: 'border-l-sky-500',
  };

  return (
    <div className={`soc-card border-l-4 ${severityBorder[finding.severity]} overflow-hidden`}>
      <button onClick={onToggle} className="w-full p-4 flex items-start justify-between gap-4 text-left hover:bg-slate-800/30 transition-colors">
        <div className="flex items-start gap-3 flex-1">
          {expanded ? <ChevronDown className="w-4 h-4 text-slate-500 shrink-0 mt-1" /> : <ChevronRight className="w-4 h-4 text-slate-500 shrink-0 mt-1" />}
          <div className="flex-1">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs text-slate-500">{finding.category}</span>
              <span className="text-xs text-slate-600">·</span>
              <span className="text-xs text-sky-400">{finding.protocol}</span>
            </div>
            <h3 className="text-sm font-semibold text-slate-200">{finding.title}</h3>
            <p className="text-xs text-slate-500 mt-1">{finding.source} → {finding.destination}</p>
          </div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-lg font-bold text-sky-400">{finding.aiPriority}</div>
          <div className="text-[10px] text-slate-500 uppercase">AI Priority</div>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-2 border-t border-slate-800/50 space-y-4">
          <FindingSection label="Evidence" text={finding.evidence} />
          <FindingSection label="Why It Matters" text={finding.impact} />
          <FindingSection label="Technical Explanation" text={finding.explanation} />
          <FindingSection label="Recommended Remediation" text={finding.remediation} />

          <div className="flex items-center gap-2 flex-wrap">
            <ConfidenceBadge confidence={finding.confidence} />
            <span className="soc-badge severity-informational">AI Risk: {finding.aiRiskLevel}</span>
            <span className="soc-badge severity-low">AI Confidence: {Math.round(finding.aiConfidence * 100)}%</span>
          </div>

          {/* AI Analysis */}
          <div className="p-3 rounded-lg bg-sky-500/5 border border-sky-500/20">
            <div className="flex items-center gap-2 mb-2">
              <Brain className="w-4 h-4 text-sky-400" />
              <span className="text-xs font-semibold text-sky-400 uppercase tracking-wide">AI Analysis</span>
            </div>
            <p className="text-sm text-slate-300">{finding.aiExplanation}</p>
            <div className="mt-2">
              <p className="text-xs text-slate-500 mb-1">Contributing features:</p>
              <div className="flex flex-wrap gap-1.5">
                {finding.aiContributingFeatures.map((feat, i) => (
                  <span key={i} className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400">{feat}</span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function FindingSection({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">{label}</p>
      <p className="text-sm text-slate-300">{text}</p>
    </div>
  );
}
