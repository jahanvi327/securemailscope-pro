import type { EmailSession, SecurityFinding, CertificateInfo, AnalysisResult, TlsInfo, StartTlsStatus, Severity } from '@/types';
import { analyzeTlsConfig } from '@/engine/tlsAnalyzer';
import { analyzeCertificate } from '@/engine/certificateAnalyzer';
import { analyzeStartTls } from '@/engine/starttlsAnalyzer';
import { calculateSecurityScore } from '@/engine/scoringEngine';
import { applyAiPrioritization } from '@/engine/aiPrioritization';
import { defaultPolicy } from '@/engine/securityPolicy';

function makeCert(
  subject: string, issuer: string, serial: string,
  validFrom: string, validUntil: string,
  sigAlg: string, keyAlg: string, keySize: number,
  san: string[], chainDepth: number | null, selfSigned: boolean,
  status: CertificateInfo['status'], statusDetail: string,
): CertificateInfo {
  return { subject, issuer, serialNumber: serial, validFrom, validUntil, signatureAlgorithm: sigAlg, publicKeyAlgorithm: keyAlg, publicKeySize: keySize, sanEntries: san, chainDepth, selfSigned, status, statusDetail };
}

function makeTls(version: TlsInfo['version'], cipher: string, fs: boolean | null): TlsInfo {
  return {
    version, cipherSuite: cipher,
    keyExchange: cipher.includes('ECDHE') ? 'ECDHE' : cipher.includes('DHE') ? 'DHE' : 'RSA',
    encryption: cipher.includes('GCM') ? 'AES-GCM' : cipher.includes('CHACHA') ? 'ChaCha20-Poly1305' : cipher.includes('CBC') ? 'AES-CBC' : 'AES-GCM',
    authentication: cipher.includes('ECDSA') ? 'ECDSA' : 'RSA',
    mac: cipher.includes('GCM') || cipher.includes('CHACHA') ? 'AEAD' : 'SHA256',
    forwardSecrecy: fs,
    isDirectTls: false,
  };
}

export function createDemoAnalysis(): AnalysisResult {
  const policy = defaultPolicy;
  const now = new Date('2026-09-25T10:00:00Z');
  const ts = (offset: number) => new Date(now.getTime() + offset * 1000).toISOString();

  const sessions: EmailSession[] = [];
  const findings: SecurityFinding[] = [];

  // Session 1: Secure TLS 1.3 SMTP
  {
    const sessionId = 'S-001';
    const cert = makeCert('mail.corp.example.com', 'Let\'s Encrypt R3', '03:AB:CD:EF:12:34:56:78', '2026-06-01', '2027-06-01', 'SHA256withRSA', 'RSA', 2048, ['mail.corp.example.com', 'corp.example.com'], 3, false, 'valid', 'Valid certificate from trusted CA.');
    const tls = makeTls('TLS 1.3', 'TLS_AES_256_GCM_SHA384', true);
    sessions.push({
      id: sessionId, timestamp: ts(0), protocol: 'SMTP', sourceIp: '10.0.1.50', destinationIp: '192.168.10.5',
      sourcePort: 54321, destinationPort: 587, sessionDuration: 12.5, hasTls: true, isStartTls: true,
      startTlsStatus: 'negotiated', tls, certificate: cert, packetCount: 48,
      riskScore: 95, riskLevel: 'informational', confidence: 'confirmed', findingIds: [],
    });
  }

  // Session 2: TLS 1.2 IMAP
  {
    const sessionId = 'S-002';
    const cert = makeCert('imap.corp.example.com', 'DigiCert TLS RSA SHA256 2020 CA1', '0A:1B:2C:3D:4E:5F', '2026-03-15', '2027-03-15', 'SHA256withRSA', 'RSA', 2048, ['imap.corp.example.com'], 3, false, 'valid', 'Valid certificate.');
    const tls = makeTls('TLS 1.2', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', true);
    sessions.push({
      id: sessionId, timestamp: ts(30), protocol: 'IMAP', sourceIp: '10.0.1.51', destinationIp: '192.168.10.6',
      sourcePort: 49832, destinationPort: 993, sessionDuration: 45.2, hasTls: true, isStartTls: false,
      startTlsStatus: 'not-observed', tls, certificate: cert, packetCount: 120,
      riskScore: 88, riskLevel: 'low', confidence: 'confirmed', findingIds: [],
    });
  }

  // Session 3: Deprecated TLS 1.0 SMTP
  {
    const sessionId = 'S-003';
    const cert = makeCert('legacy-mail.corp.example.com', 'GeoTrust TLS RSA CA G1', '1F:2E:3D:4C:5B:6A', '2025-01-10', '2026-01-10', 'SHA1withRSA', 'RSA', 1024, ['legacy-mail.corp.example.com'], 2, false, 'expired', 'Certificate expired on 2026-01-10.');
    const tls = makeTls('TLS 1.0', 'TLS_RSA_WITH_AES_128_CBC_SHA', false);
    const tlsFindings = analyzeTlsConfig('TLS 1.0', 'TLS_RSA_WITH_AES_128_CBC_SHA', policy, 'SMTP', '10.0.1.52', '192.168.10.7', sessionId, ts(60));
    const certFindings = analyzeCertificate(cert, policy, 'SMTP', '10.0.1.52', '192.168.10.7', sessionId, ts(60));
    const allF = [...tlsFindings.findings, ...certFindings];
    findings.push(...allF);
    sessions.push({
      id: sessionId, timestamp: ts(60), protocol: 'SMTP', sourceIp: '10.0.1.52', destinationIp: '192.168.10.7',
      sourcePort: 45123, destinationPort: 25, sessionDuration: 8.3, hasTls: true, isStartTls: true,
      startTlsStatus: 'negotiated', tls, certificate: cert, packetCount: 32,
      riskScore: 28, riskLevel: 'high', confidence: 'confirmed', findingIds: allF.map(f => f.id),
    });
  }

  // Session 4: Expired certificate IMAP
  {
    const sessionId = 'S-004';
    const cert = makeCert('mail-old.corp.example.com', 'Sectigo RSA Domain Validation Secure Server CA', '7B:8C:9D:0E:1F:2A', '2024-08-01', '2025-08-01', 'SHA256withRSA', 'RSA', 2048, ['mail-old.corp.example.com'], 3, false, 'expired', 'Certificate expired on 2025-08-01.');
    const tls = makeTls('TLS 1.2', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', true);
    const certFindings = analyzeCertificate(cert, policy, 'IMAP', '10.0.1.53', '192.168.10.8', sessionId, ts(90));
    findings.push(...certFindings);
    sessions.push({
      id: sessionId, timestamp: ts(90), protocol: 'IMAP', sourceIp: '10.0.1.53', destinationIp: '192.168.10.8',
      sourcePort: 51234, destinationPort: 143, sessionDuration: 22.1, hasTls: true, isStartTls: true,
      startTlsStatus: 'negotiated', tls, certificate: cert, packetCount: 65,
      riskScore: 55, riskLevel: 'medium', confidence: 'confirmed', findingIds: certFindings.map(f => f.id),
    });
  }

  // Session 5: Weak certificate (self-signed, SHA1)
  {
    const sessionId = 'S-005';
    const cert = makeCert('internal-mail.corp.example.com', 'internal-mail.corp.example.com', '00:00:00:00:00:01', '2026-01-01', '2029-01-01', 'SHA1withRSA', 'RSA', 1024, ['internal-mail.corp.example.com'], 1, true, 'weak-signature', 'Self-signed with SHA1 and 1024-bit RSA.');
    const tls = makeTls('TLS 1.2', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', true);
    const tlsFindings = analyzeTlsConfig('TLS 1.2', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', policy, 'POP3', '10.0.1.54', '192.168.10.9', sessionId, ts(120));
    const certFindings = analyzeCertificate(cert, policy, 'POP3', '10.0.1.54', '192.168.10.9', sessionId, ts(120));
    const allF = [...tlsFindings.findings, ...certFindings];
    findings.push(...allF);
    sessions.push({
      id: sessionId, timestamp: ts(120), protocol: 'POP3', sourceIp: '10.0.1.54', destinationIp: '192.168.10.9',
      sourcePort: 38472, destinationPort: 110, sessionDuration: 15.7, hasTls: true, isStartTls: true,
      startTlsStatus: 'negotiated', tls, certificate: cert, packetCount: 40,
      riskScore: 42, riskLevel: 'medium', confidence: 'confirmed', findingIds: allF.map(f => f.id),
    });
  }

  // Session 6: Plaintext SMTP (no STARTTLS)
  {
    const sessionId = 'S-006';
    const startTlsFindings = analyzeStartTls('plaintext', 'SMTP', '10.0.1.55', '192.168.10.10', sessionId, ts(150), policy);
    findings.push(...startTlsFindings);
    sessions.push({
      id: sessionId, timestamp: ts(150), protocol: 'SMTP', sourceIp: '10.0.1.55', destinationIp: '192.168.10.10',
      sourcePort: 47821, destinationPort: 25, sessionDuration: 5.2, hasTls: false, isStartTls: false,
      startTlsStatus: 'plaintext', tls: null, certificate: null, packetCount: 18,
      riskScore: 15, riskLevel: 'critical', confidence: 'confirmed', findingIds: startTlsFindings.map(f => f.id),
    });
  }

  // Session 7: POP3 STARTTLS offered but not negotiated
  {
    const sessionId = 'S-007';
    const startTlsFindings = analyzeStartTls('offered', 'POP3', '10.0.1.56', '192.168.10.11', sessionId, ts(180), policy);
    findings.push(...startTlsFindings);
    sessions.push({
      id: sessionId, timestamp: ts(180), protocol: 'POP3', sourceIp: '10.0.1.56', destinationIp: '192.168.10.11',
      sourcePort: 39201, destinationPort: 110, sessionDuration: 3.8, hasTls: false, isStartTls: false,
      startTlsStatus: 'offered', tls: null, certificate: null, packetCount: 12,
      riskScore: 60, riskLevel: 'low', confidence: 'possible', findingIds: startTlsFindings.map(f => f.id),
    });
  }

  // Session 8: TLS 1.1 deprecated
  {
    const sessionId = 'S-008';
    const cert = makeCert('smtp.partner.example.org', 'GlobalSign GCC R3 DV TLS CA 2020', '4D:5E:6F:70:81:92', '2026-02-01', '2027-02-01', 'SHA256withRSA', 'RSA', 2048, ['smtp.partner.example.org'], 3, false, 'valid', 'Valid certificate.');
    const tls = makeTls('TLS 1.1', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', true);
    const tlsFindings = analyzeTlsConfig('TLS 1.1', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', policy, 'SMTP', '10.0.1.57', '192.168.10.12', sessionId, ts(210));
    findings.push(...tlsFindings.findings);
    sessions.push({
      id: sessionId, timestamp: ts(210), protocol: 'SMTP', sourceIp: '10.0.1.57', destinationIp: '192.168.10.12',
      sourcePort: 56789, destinationPort: 587, sessionDuration: 18.4, hasTls: true, isStartTls: true,
      startTlsStatus: 'negotiated', tls, certificate: cert, packetCount: 55,
      riskScore: 50, riskLevel: 'medium', confidence: 'confirmed', findingIds: tlsFindings.findings.map(f => f.id),
    });
  }

  // Session 9: Secure IMAP TLS 1.3
  {
    const sessionId = 'S-009';
    const cert = makeCert('imap-secure.corp.example.com', 'Amazon RSA 2048 M02', '9A:8B:7C:6D:5E:4F', '2026-07-01', '2027-07-01', 'SHA256withRSA', 'RSA', 2048, ['imap-secure.corp.example.com'], 3, false, 'valid', 'Valid certificate.');
    const tls = makeTls('TLS 1.3', 'TLS_CHACHA20_POLY1305_SHA256', true);
    sessions.push({
      id: sessionId, timestamp: ts(240), protocol: 'IMAP', sourceIp: '10.0.1.58', destinationIp: '192.168.10.13',
      sourcePort: 62345, destinationPort: 993, sessionDuration: 30.0, hasTls: true, isStartTls: false,
      startTlsStatus: 'not-observed', tls, certificate: cert, packetCount: 88,
      riskScore: 98, riskLevel: 'informational', confidence: 'confirmed', findingIds: [],
    });
  }

  // Session 10: SMTP with weak cipher (RC4)
  {
    const sessionId = 'S-010';
    const cert = makeCert('old-smtp.corp.example.com', 'COMODO RSA Domain Validation Secure Server CA', '2B:3C:4D:5E:6F:70', '2025-11-01', '2026-11-01', 'SHA256withRSA', 'RSA', 2048, ['old-smtp.corp.example.com'], 3, false, 'valid', 'Valid certificate.');
    const tls = makeTls('TLS 1.2', 'TLS_RSA_WITH_RC4_128_SHA', false);
    const tlsFindings = analyzeTlsConfig('TLS 1.2', 'TLS_RSA_WITH_RC4_128_SHA', policy, 'SMTP', '10.0.1.59', '192.168.10.14', sessionId, ts(270));
    findings.push(...tlsFindings.findings);
    sessions.push({
      id: sessionId, timestamp: ts(270), protocol: 'SMTP', sourceIp: '10.0.1.59', destinationIp: '192.168.10.14',
      sourcePort: 41023, destinationPort: 465, sessionDuration: 10.1, hasTls: true, isStartTls: false,
      startTlsStatus: 'not-observed', tls, certificate: cert, packetCount: 28,
      riskScore: 35, riskLevel: 'high', confidence: 'confirmed', findingIds: tlsFindings.findings.map(f => f.id),
    });
  }

  // Apply AI prioritization
  const prioritizedFindings = applyAiPrioritization(findings, sessions);

  // Update session finding IDs with prioritized findings
  const updatedSessions = sessions.map(s => ({
    ...s,
    findingIds: prioritizedFindings.filter(f => f.sessionId === s.id).map(f => f.id),
  }));

  const score = calculateSecurityScore(updatedSessions, prioritizedFindings, policy);

  return buildAnalysisResult('demo-synthetic-dataset.pcap', 0, true, updatedSessions, prioritizedFindings, score);
}

export function buildAnalysisResult(
  fileName: string,
  fileSize: number,
  isDemo: boolean,
  sessions: EmailSession[],
  findings: SecurityFinding[],
  score: AnalysisResult['score'],
): AnalysisResult {
  const tlsVersionDistribution = computeTlsVersionDistribution(sessions);
  const cipherDistribution = computeCipherDistribution(sessions);
  const certificateStatusDistribution = computeCertStatusDistribution(sessions);
  const findingsByProtocol = computeFindingsByProtocol(findings);
  const findingsTimeline = computeFindingsTimeline(findings);
  const topRiskyHosts = computeTopRiskyHosts(sessions, findings);

  return {
    id: `analysis-${Date.now()}`,
    fileName,
    fileSize,
    uploadedAt: new Date().toISOString(),
    isDemo,
    sessions,
    findings,
    score,
    tlsVersionDistribution,
    cipherDistribution,
    certificateStatusDistribution,
    findingsByProtocol,
    findingsTimeline,
    topRiskyHosts,
  };
}

function computeTlsVersionDistribution(sessions: EmailSession[]) {
  const tlsSessions = sessions.filter(s => s.hasTls && s.tls);
  const total = tlsSessions.length || 1;
  const counts = new Map<string, number>();
  for (const s of tlsSessions) {
    const v = s.tls!.version;
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  return Array.from(counts.entries()).map(([version, count]) => ({
    version, count, percentage: Math.round((count / total) * 100),
  }));
}

function computeCipherDistribution(sessions: EmailSession[]) {
  const counts = new Map<string, number>();
  for (const s of sessions) {
    if (s.tls) counts.set(s.tls.cipherSuite, (counts.get(s.tls.cipherSuite) || 0) + 1);
  }
  return Array.from(counts.entries()).map(([cipher, count]) => ({ cipher, count }));
}

function computeCertStatusDistribution(sessions: EmailSession[]) {
  const counts = new Map<string, number>();
  for (const s of sessions) {
    if (s.certificate) counts.set(s.certificate.status, (counts.get(s.certificate.status) || 0) + 1);
  else counts.set('no-certificate', (counts.get('no-certificate') || 0) + 1);
  }
  return Array.from(counts.entries()).map(([status, count]) => ({ status, count }));
}

function computeFindingsByProtocol(findings: SecurityFinding[]) {
  const counts = new Map<string, number>();
  for (const f of findings) {
    counts.set(f.protocol, (counts.get(f.protocol) || 0) + 1);
  }
  return Array.from(counts.entries()).map(([protocol, count]) => ({ protocol, count }));
}

function computeFindingsTimeline(findings: SecurityFinding[]) {
  const counts = new Map<string, { time: string; severity: Severity; count: number }>();
  for (const f of findings) {
    const timeKey = f.timestamp.split('T')[1]?.substring(0, 5) || f.timestamp;
    const key = `${timeKey}-${f.severity}`;
    if (!counts.has(key)) {
      counts.set(key, { time: timeKey, severity: f.severity, count: 0 });
    }
    counts.get(key)!.count++;
  }
  return Array.from(counts.values()).sort((a, b) => a.time.localeCompare(b.time));
}

function computeTopRiskyHosts(sessions: EmailSession[], findings: SecurityFinding[]) {
  const hostMap = new Map<string, { riskScore: number; findingCount: number; count: number }>();
  for (const s of sessions) {
    const host = s.destinationIp;
    if (!hostMap.has(host)) hostMap.set(host, { riskScore: 0, findingCount: 0, count: 0 });
    const entry = hostMap.get(host)!;
    entry.riskScore += s.riskScore;
    entry.count++;
    entry.findingCount += s.findingIds.length;
  }
  return Array.from(hostMap.entries())
    .map(([host, data]) => ({ host, riskScore: Math.round(data.riskScore / data.count), findingCount: data.findingCount }))
    .sort((a, b) => a.riskScore - b.riskScore)
    .slice(0, 10);
}
