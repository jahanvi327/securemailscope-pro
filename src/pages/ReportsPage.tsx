import type { AnalysisResult } from '@/types';
import { exportJSON, exportCSV, exportHTML, exportPDF } from '@/services/reportGenerator';
import { FileText, FileJson, FileSpreadsheet, FileCode, Download, FileCheck } from 'lucide-react';

interface ReportsPageProps {
  result: AnalysisResult;
}

export function ReportsPage({ result }: ReportsPageProps) {
  const s = result.score;

  return (
    <div className="max-w-4xl mx-auto animate-fade-in">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-slate-100">Report Generation</h2>
        <p className="text-sm text-slate-500 mt-1">Export the full security analysis in multiple formats</p>
      </div>

      {/* Report summary */}
      <div className="soc-card p-6 mb-6">
        <div className="flex items-center gap-3 mb-4">
          <FileCheck className="w-5 h-5 text-sky-400" />
          <h3 className="text-sm font-semibold text-slate-200">Report Summary</h3>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <ReportStat label="Security Score" value={`${s.overall}/100`} color={s.overall >= 80 ? 'text-emerald-400' : s.overall >= 60 ? 'text-amber-400' : 'text-red-400'} />
          <ReportStat label="Risk Level" value={s.riskLevel.toUpperCase()} color={s.riskLevel === 'critical' ? 'text-red-400' : s.riskLevel === 'high' ? 'text-orange-400' : s.riskLevel === 'medium' ? 'text-amber-400' : 'text-emerald-400'} />
          <ReportStat label="Total Sessions" value={String(result.sessions.length)} color="text-sky-400" />
          <ReportStat label="Total Findings" value={String(s.totalFindings)} color="text-amber-400" />
        </div>
      </div>

      {/* Export options */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ExportCard
          icon={FileText}
          title="PDF Report"
          description="Professional report with cover page, executive summary, score breakdown, sessions, findings, AI prioritization, and technical appendix."
          buttonText="Download PDF"
          onClick={() => exportPDF(result)}
          color="text-red-400"
          bg="bg-red-500/10"
        />
        <ExportCard
          icon={FileCode}
          title="HTML Report"
          description="Self-contained HTML report with styled tables, score breakdown, and detailed findings. Opens in any browser."
          buttonText="Download HTML"
          onClick={() => exportHTML(result)}
          color="text-orange-400"
          bg="bg-orange-500/10"
        />
        <ExportCard
          icon={FileJson}
          title="JSON Export"
          description="Complete machine-readable analysis data including all sessions, findings, scores, and distributions."
          buttonText="Download JSON"
          onClick={() => exportJSON(result)}
          color="text-amber-400"
          bg="bg-amber-500/10"
        />
        <ExportCard
          icon={FileSpreadsheet}
          title="CSV Findings"
          description="Spreadsheet of all security findings with severity, category, protocol, confidence, and AI priority scores."
          buttonText="Download CSV"
          onClick={() => exportCSV(result)}
          color="text-emerald-400"
          bg="bg-emerald-500/10"
        />
      </div>

      {/* Report contents */}
      <div className="soc-card p-6 mt-6">
        <h3 className="text-sm font-semibold text-slate-200 mb-4">Report Contents</h3>
        <div className="space-y-2">
          {[
            'Cover page with security score and risk level',
            'Executive summary with key metrics',
            'Security score breakdown (6 factors)',
            'TLS version and cipher suite distribution',
            'Certificate status analysis',
            'Complete session table',
            'All security findings with evidence and remediation',
            'AI-assisted prioritization and explanations',
            'Technical appendix with limitations',
          ].map((item, i) => (
            <div key={i} className="flex items-center gap-2 text-sm text-slate-400">
              <FileCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              {item}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ReportStat({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="text-center p-3 rounded-lg bg-slate-800/50">
      <div className={`text-xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-500 mt-1">{label}</div>
    </div>
  );
}

function ExportCard({ icon: Icon, title, description, buttonText, onClick, color, bg }: {
  icon: typeof FileText; title: string; description: string; buttonText: string; onClick: () => void; color: string; bg: string;
}) {
  return (
    <div className="soc-card p-6 flex flex-col">
      <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-4 ${bg}`}>
        <Icon className={`w-6 h-6 ${color}`} />
      </div>
      <h3 className="text-base font-semibold text-slate-100 mb-2">{title}</h3>
      <p className="text-sm text-slate-400 flex-1">{description}</p>
      <button
        onClick={onClick}
        className="mt-4 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 text-sm font-medium hover:bg-slate-700 hover:border-slate-600 transition-colors"
      >
        <Download className="w-4 h-4" />
        {buttonText}
      </button>
    </div>
  );
}
