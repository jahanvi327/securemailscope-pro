import type { AnalysisResult } from '@/types';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

export function exportJSON(result: AnalysisResult): void {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `securemailscope-${result.fileName}-report.json`);
}

export function exportCSV(result: AnalysisResult): void {
  const rows: string[] = [];
  rows.push('ID,Severity,Category,Title,Protocol,Source,Destination,Confidence,AI Priority,AI Risk Level,Session ID,Timestamp');
  for (const f of result.findings) {
    const esc = (s: string) => `"${s.replace(/"/g, '""')}"`;
    rows.push([
      esc(f.id), esc(f.severity), esc(f.category), esc(f.title), esc(f.protocol),
      esc(f.source), esc(f.destination), esc(f.confidence), String(f.aiPriority),
      esc(f.aiRiskLevel), esc(f.sessionId || ''), esc(f.timestamp),
    ].join(','));
  }
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
  downloadBlob(blob, `securemailscope-${result.fileName}-findings.csv`);
}

export function exportHTML(result: AnalysisResult): void {
  const html = generateHTMLReport(result);
  const blob = new Blob([html], { type: 'text/html' });
  downloadBlob(blob, `securemailscope-${result.fileName}-report.html`);
}

function generateHTMLReport(result: AnalysisResult): string {
  const s = result.score;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureMailScope Report — ${escapeHtml(result.fileName)}</title>
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 40px; }
  h1 { color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 10px; }
  h2 { color: #7dd3fc; margin-top: 32px; }
  .card { background: #1e293b; border-radius: 12px; padding: 20px; margin: 16px 0; }
  .score { font-size: 48px; font-weight: bold; color: ${scoreColor(s.overall)}; }
  .risk { font-size: 20px; font-weight: bold; color: ${severityColor(s.riskLevel)}; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  th { background: #334155; padding: 10px; text-align: left; color: #94a3b8; }
  td { padding: 10px; border-bottom: 1px solid #334155; }
  .severity-critical { color: #f87171; font-weight: bold; }
  .severity-high { color: #fb923c; font-weight: bold; }
  .severity-medium { color: #fbbf24; font-weight: bold; }
  .severity-low { color: #34d399; font-weight: bold; }
  .severity-informational { color: #60a5fa; font-weight: bold; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
  .footer { margin-top: 40px; color: #64748b; font-size: 12px; text-align: center; }
</style>
</head>
<body>
<h1>SecureMailScope Security Report</h1>
<p>File: ${escapeHtml(result.fileName)} | Analyzed: ${new Date(result.uploadedAt).toLocaleString()}${result.isDemo ? ' | <span style="color:#fbbf24">SYNTHETIC DEMO DATA</span>' : ''}</p>

<div class="card">
  <h2>Executive Summary</h2>
  <p><span class="score">${s.overall}/100</span> &mdash; <span class="risk">${s.riskLevel.toUpperCase()} RISK</span></p>
  <p>Total Findings: ${s.totalFindings} | Critical: ${s.criticalCount} | High: ${s.highCount} | Medium: ${s.mediumCount} | Low: ${s.lowCount}</p>
</div>

<div class="card">
  <h2>Score Breakdown</h2>
  <table>
    <tr><th>Factor</th><th>Score</th></tr>
    <tr><td>TLS Configuration</td><td>${s.breakdown.tlsConfiguration}/100</td></tr>
    <tr><td>Certificate Security</td><td>${s.breakdown.certificateSecurity}/100</td></tr>
    <tr><td>Protocol Security</td><td>${s.breakdown.protocolSecurity}/100</td></tr>
    <tr><td>Encryption Coverage</td><td>${s.breakdown.encryptionCoverage}/100</td></tr>
    <tr><td>Cryptographic Strength</td><td>${s.breakdown.cryptographicStrength}/100</td></tr>
    <tr><td>Configuration Weaknesses</td><td>${s.breakdown.configurationWeaknesses}/100</td></tr>
  </table>
</div>

<div class="card">
  <h2>Sessions (${result.sessions.length})</h2>
  <table>
    <tr><th>ID</th><th>Protocol</th><th>Source</th><th>Destination</th><th>TLS</th><th>Risk</th></tr>
    ${result.sessions.map(sess => `<tr><td>${sess.id}</td><td>${sess.protocol}</td><td>${escapeHtml(sess.sourceIp)}</td><td>${escapeHtml(sess.destinationIp)}</td><td>${sess.hasTls ? 'Yes' : 'No'}</td><td class="severity-${sess.riskLevel}">${sess.riskLevel.toUpperCase()}</td></tr>`).join('')}
  </table>
</div>

<div class="card">
  <h2>Security Findings (${result.findings.length})</h2>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Title</th><th>Protocol</th><th>Confidence</th><th>AI Priority</th></tr>
    ${result.findings.map(f => `<tr><td class="severity-${f.severity}">${f.severity.toUpperCase()}</td><td>${escapeHtml(f.category)}</td><td>${escapeHtml(f.title)}</td><td>${f.protocol}</td><td>${f.confidence}</td><td>${f.aiPriority}</td></tr>`).join('')}
  </table>
</div>

<div class="card">
  <h2>Detailed Findings</h2>
  ${result.findings.map(f => `
  <div style="margin-bottom:24px; padding:16px; background:#0f172a; border-radius:8px; border-left:4px solid ${severityColor(f.severity)};">
    <h3 style="color:${severityColor(f.severity)}">${f.severity.toUpperCase()} — ${escapeHtml(f.title)}</h3>
    <p><strong>Protocol:</strong> ${f.protocol} | <strong>Source:</strong> ${escapeHtml(f.source)} | <strong>Destination:</strong> ${escapeHtml(f.destination)}</p>
    <p><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</p>
    <p><strong>Impact:</strong> ${escapeHtml(f.impact)}</p>
    <p><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</p>
    <p><strong>Confidence:</strong> ${f.confidence} | <strong>AI Priority:</strong> ${f.aiPriority}/100 | <strong>AI Risk:</strong> ${f.aiRiskLevel}</p>
    <p><em>AI: ${escapeHtml(f.aiExplanation)}</em></p>
  </div>`).join('')}
</div>

<div class="footer">
  <p>Generated by SecureMailScope — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications</p>
  <p>This is a defensive security tool. All analysis is passive and based on user-provided PCAP files.</p>
</div>
</body>
</html>`;
}

export function exportPDF(result: AnalysisResult): void {
  const doc = new jsPDF('p', 'mm', 'a4');
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  let y = margin;

  // Cover page
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, pageHeight, 'F');
  doc.setTextColor(56, 189, 248);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('SecureMailScope', pageWidth / 2, 60, { align: 'center' });
  doc.setFontSize(14);
  doc.setTextColor(226, 232, 240);
  doc.setFont('helvetica', 'normal');
  doc.text('Security Posture Assessment Report', pageWidth / 2, 75, { align: 'center' });
  doc.setFontSize(10);
  doc.setTextColor(148, 163, 184);
  doc.text(`File: ${result.fileName}`, pageWidth / 2, 95, { align: 'center' });
  doc.text(`Date: ${new Date(result.uploadedAt).toLocaleString()}`, pageWidth / 2, 102, { align: 'center' });
  if (result.isDemo) {
    doc.setTextColor(251, 191, 36);
    doc.text('SYNTHETIC DEMO DATA', pageWidth / 2, 112, { align: 'center' });
  }

  // Score circle
  doc.setTextColor(...scoreColorRgb(result.score.overall));
  doc.setFontSize(48);
  doc.setFont('helvetica', 'bold');
  doc.text(`${result.score.overall}`, pageWidth / 2 - 8, 150, { align: 'center' });
  doc.setFontSize(14);
  doc.text('/100', pageWidth / 2 + 18, 150, { align: 'center' });
  doc.setFontSize(16);
  doc.text(`${result.score.riskLevel.toUpperCase()} RISK`, pageWidth / 2, 165, { align: 'center' });

  doc.addPage();

  // Executive Summary
  y = addSectionHeader(doc, 'Executive Summary', margin, y);
  doc.setTextColor(50, 50, 50);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  const summaryLines = [
    `Overall Security Score: ${result.score.overall}/100`,
    `Risk Level: ${result.score.riskLevel.toUpperCase()}`,
    `Total Sessions: ${result.sessions.length}`,
    `Total Findings: ${result.score.totalFindings}`,
    `Critical: ${result.score.criticalCount}  High: ${result.score.highCount}  Medium: ${result.score.mediumCount}  Low: ${result.score.lowCount}`,
  ];
  for (const line of summaryLines) {
    doc.text(line, margin, y);
    y += 6;
  }
  y += 4;

  // Score breakdown
  y = addSectionHeader(doc, 'Security Score Breakdown', margin, y);
  autoTable(doc, {
    startY: y,
    head: [['Factor', 'Score']],
    body: [
      ['TLS Configuration', `${result.score.breakdown.tlsConfiguration}/100`],
      ['Certificate Security', `${result.score.breakdown.certificateSecurity}/100`],
      ['Protocol Security', `${result.score.breakdown.protocolSecurity}/100`],
      ['Encryption Coverage', `${result.score.breakdown.encryptionCoverage}/100`],
      ['Cryptographic Strength', `${result.score.breakdown.cryptographicStrength}/100`],
      ['Configuration Weaknesses', `${result.score.breakdown.configurationWeaknesses}/100`],
    ],
    theme: 'striped',
    headStyles: { fillColor: [30, 41, 59], textColor: [148, 163, 184] },
    styles: { fontSize: 9 },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  // TLS Distribution
  if (y > pageHeight - 60) { doc.addPage(); y = margin; }
  y = addSectionHeader(doc, 'TLS Version Distribution', margin, y);
  autoTable(doc, {
    startY: y,
    head: [['TLS Version', 'Sessions', 'Percentage']],
    body: result.tlsVersionDistribution.map(t => [t.version, String(t.count), `${t.percentage}%`]),
    theme: 'striped',
    headStyles: { fillColor: [30, 41, 59] },
    styles: { fontSize: 9 },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  // Sessions table
  if (y > pageHeight - 60) { doc.addPage(); y = margin; }
  y = addSectionHeader(doc, `Email Sessions (${result.sessions.length})`, margin, y);
  autoTable(doc, {
    startY: y,
    head: [['ID', 'Protocol', 'Source', 'Destination', 'TLS', 'Risk']],
    body: result.sessions.map(s => [s.id, s.protocol, s.sourceIp, s.destinationIp, s.hasTls ? 'Yes' : 'No', s.riskLevel.toUpperCase()]),
    theme: 'striped',
    headStyles: { fillColor: [30, 41, 59] },
    styles: { fontSize: 8 },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  // Findings
  if (y > pageHeight - 40) { doc.addPage(); y = margin; }
  y = addSectionHeader(doc, `Security Findings (${result.findings.length})`, margin, y);
  autoTable(doc, {
    startY: y,
    head: [['Severity', 'Category', 'Title', 'Protocol', 'AI Priority']],
    body: result.findings.map(f => [f.severity.toUpperCase(), f.category, f.title, f.protocol, `${f.aiPriority}/100`]),
    theme: 'striped',
    headStyles: { fillColor: [30, 41, 59] },
    styles: { fontSize: 8 },
    columnStyles: { 0: { cellWidth: 25 } },
  });
  y = (doc as any).lastAutoTable.finalY + 10;

  // Detailed findings
  for (const f of result.findings) {
    if (y > pageHeight - 60) { doc.addPage(); y = margin; }
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...severityColorRgb(f.severity));
    doc.text(`${f.severity.toUpperCase()} — ${f.title}`, margin, y);
    y += 6;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(50, 50, 50);
    y = addWrappedText(doc, `Protocol: ${f.protocol} | Source: ${f.source} | Destination: ${f.destination}`, margin, y, pageWidth - 2 * margin);
    y = addWrappedText(doc, `Evidence: ${f.evidence}`, margin, y, pageWidth - 2 * margin);
    y = addWrappedText(doc, `Impact: ${f.impact}`, margin, y, pageWidth - 2 * margin);
    y = addWrappedText(doc, `Remediation: ${f.remediation}`, margin, y, pageWidth - 2 * margin);
    y = addWrappedText(doc, `Confidence: ${f.confidence} | AI Priority: ${f.aiPriority}/100`, margin, y, pageWidth - 2 * margin);
    y = addWrappedText(doc, `AI: ${f.aiExplanation}`, margin, y, pageWidth - 2 * margin);
    y += 6;
  }

  // Technical appendix
  doc.addPage();
  y = margin;
  y = addSectionHeader(doc, 'Technical Appendix', margin, y);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(50, 50, 50);
  const appendix = [
    'SecureMailScope performs passive analysis of user-provided PCAP files.',
    'It does NOT perform active attacks, exploitation, or interception.',
    '',
    'Limitations of passive PCAP analysis:',
    '- Encrypted application payloads cannot be inspected.',
    '- Private keys are not available and are never extracted.',
    '- Complete certificate chains may not be present in the capture.',
    '- Traffic outside the captured interface is not analyzed.',
    '- Configuration that never appears in network traffic cannot be assessed.',
    '',
    'AI Component:',
    'The AI component uses a feature-based prioritization model that weights deterministic',
    'findings by severity, confidence, protocol, and category. It does not invent evidence',
    'and bases all explanations on extracted packet features only.',
    '',
    'Security Score Calculation:',
    'The overall score is a weighted sum of six sub-scores: TLS configuration, certificate',
    'security, protocol security, encryption coverage, cryptographic strength, and',
    'configuration weaknesses. Each sub-score is derived from deterministic analysis',
    'of the observed sessions and findings.',
  ];
  for (const line of appendix) {
    if (y > pageHeight - 15) { doc.addPage(); y = margin; }
    doc.text(line, margin, y);
    y += 5;
  }

  doc.save(`securemailscope-${result.fileName}-report.pdf`);
}

function addSectionHeader(doc: jsPDF, text: string, x: number, y: number): number {
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text(text, x, y);
  doc.setDrawColor(56, 189, 248);
  doc.setLineWidth(0.5);
  doc.line(x, y + 2, doc.internal.pageSize.getWidth() - x, y + 2);
  return y + 8;
}

function addWrappedText(doc: jsPDF, text: string, x: number, y: number, maxWidth: number): number {
  const lines = doc.splitTextToSize(text, maxWidth);
  for (const line of lines) {
    doc.text(line, x, y);
    y += 5;
  }
  return y + 1;
}

function scoreColor(score: number): string {
  if (score >= 80) return '#34d399';
  if (score >= 60) return '#fbbf24';
  if (score >= 40) return '#fb923c';
  return '#f87171';
}

function scoreColorRgb(score: number): [number, number, number] {
  if (score >= 80) return [52, 211, 153];
  if (score >= 60) return [251, 191, 36];
  if (score >= 40) return [251, 146, 60];
  return [248, 113, 113];
}

function severityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#34d399', informational: '#60a5fa',
  };
  return colors[severity] || '#94a3b8';
}

function severityColorRgb(severity: string): [number, number, number] {
  const colors: Record<string, [number, number, number]> = {
    critical: [248, 113, 113], high: [251, 146, 60], medium: [251, 191, 36], low: [52, 211, 153], informational: [96, 165, 250],
  };
  return colors[severity] || [148, 163, 184];
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
