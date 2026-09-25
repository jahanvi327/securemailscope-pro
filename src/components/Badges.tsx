import type { Severity, Confidence } from '@/types';

export function SeverityBadge({ severity }: { severity: Severity }) {
  const cls = `severity-${severity}`;
  return <span className={`soc-badge ${cls}`}>{severity.charAt(0).toUpperCase() + severity.slice(1)}</span>;
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const colors: Record<Confidence, string> = {
    confirmed: 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20',
    possible: 'text-amber-400 bg-amber-500/10 border border-amber-500/20',
    'insufficient-data': 'text-slate-400 bg-slate-500/10 border border-slate-500/20',
  };
  const labels: Record<Confidence, string> = {
    confirmed: 'Confirmed',
    possible: 'Possible',
    'insufficient-data': 'Insufficient Data',
  };
  return <span className={`soc-badge ${colors[confidence]}`}>{labels[confidence]}</span>;
}

export function ScoreGauge({ score, size = 160 }: { score: number; size?: number }) {
  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? '#34d399' : score >= 60 ? '#fbbf24' : score >= 40 ? '#fb923c' : '#f87171';
  const riskLabel = score >= 80 ? 'Low Risk' : score >= 60 ? 'Medium Risk' : score >= 40 ? 'High Risk' : 'Critical Risk';

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#1e293b" strokeWidth="10" />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.8s ease-out' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs text-slate-500 mt-1">/ 100</span>
        <span className="text-xs font-semibold mt-1" style={{ color }}>{riskLabel}</span>
      </div>
    </div>
  );
}
