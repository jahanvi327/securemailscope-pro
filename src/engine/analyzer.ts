import type { AnalysisResult, EmailSession, SecurityFinding, CertificateInfo, StartTlsStatus, EmailProtocol, TlsInfo, TlsVersion } from '@/types';
import { parsePcap, detectProtocol, detectStartTlsFromPayload, detectTlsVersionFromPayload, extractCipherSuiteFromPayload, type TcpStream } from '@/engine/pcapParser';
import { analyzeTlsConfig } from '@/engine/tlsAnalyzer';
import { analyzeCertificate, determineCertStatus } from '@/engine/certificateAnalyzer';
import { analyzeStartTls } from '@/engine/starttlsAnalyzer';
import { calculateSecurityScore } from '@/engine/scoringEngine';
import { applyAiPrioritization } from '@/engine/aiPrioritization';
import { defaultPolicy, type SecurityPolicy } from '@/engine/securityPolicy';
import { buildAnalysisResult, createDemoAnalysis } from '@/engine/demoData';

export interface UploadValidation {
  valid: boolean;
  error?: string;
  fileName: string;
  fileSize: number;
}

export const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB

export function validateFile(file: File): UploadValidation {
  if (!file.name.match(/\.(pcap|pcapng|cap)$/i)) {
    return { valid: false, error: 'Invalid file type. Only .pcap, .pcapng, and .cap files are accepted.', fileName: file.name, fileSize: file.size };
  }
  if (file.size === 0) {
    return { valid: false, error: 'File is empty.', fileName: file.name, fileSize: file.size };
  }
  if (file.size > MAX_FILE_SIZE) {
    return { valid: false, error: `File exceeds maximum size of ${MAX_FILE_SIZE / 1024 / 1024} MB.`, fileName: file.name, fileSize: file.size };
  }
  return { valid: true, fileName: file.name, fileSize: file.size };
}

export function analyzePcapFile(buffer: ArrayBuffer, fileName: string, fileSize: number, policy: SecurityPolicy = defaultPolicy): AnalysisResult {
  const parseResult = parsePcap(buffer);

  if (!parseResult.valid) {
    throw new Error(parseResult.error || 'Invalid PCAP file.');
  }

  if (parseResult.emailStreams.length === 0) {
    // No email sessions found — return an empty analysis with informational finding
    const sessions: EmailSession[] = [];
    const findings: SecurityFinding[] = [{
      id: 'F-INFO-NOEMAIL',
      severity: 'informational',
      category: 'Analysis',
      title: 'No Email Protocol Sessions Detected',
      protocol: 'General',
      source: 'N/A',
      destination: 'N/A',
      evidence: `Parsed ${parseResult.packetCount} packets but found no TCP sessions on SMTP (25/587/465), IMAP (143/993), or POP3 (110/995) ports.`,
      explanation: 'The PCAP file does not contain traffic on recognized email protocol ports. This could mean the capture was on the wrong interface, the traffic uses non-standard ports, or no email traffic was present.',
      impact: 'No email security assessment can be performed on this capture.',
      remediation: 'Ensure the PCAP captures traffic on the correct interface and includes email server communications.',
      confidence: 'confirmed',
      sessionId: null,
      timestamp: new Date().toISOString(),
      aiPriority: 10, aiRiskLevel: 'informational', aiConfidence: 0.5, aiContributingFeatures: ['No email sessions found'], aiExplanation: 'No email traffic detected for analysis.',
    }];
    const score = calculateSecurityScore(sessions, findings, policy);
    return buildAnalysisResult(fileName, fileSize, false, sessions, findings, score);
  }

  const sessions: EmailSession[] = [];
  const findings: SecurityFinding[] = [];

  for (const stream of parseResult.emailStreams) {
    const protocol = detectProtocol(stream.dstPort) || detectProtocol(stream.srcPort);
    if (!protocol) continue;

    const sessionId = `S-${sessions.length + 1}`;
    const timestamp = stream.packets.length > 0
      ? new Date(stream.packets[0].timestamp * 1000).toISOString()
      : new Date().toISOString();
    const duration = stream.packets.length > 1
      ? (stream.packets[stream.packets.length - 1].timestamp - stream.packets[0].timestamp)
      : 0;

    const startTlsStatus: StartTlsStatus = detectStartTlsFromPayload(stream.payload);
    const tlsVersion = detectTlsVersionFromPayload(stream.payload);
    const cipherSuite = extractCipherSuiteFromPayload(stream.payload);

    const hasTls = tlsVersion !== null;
    const isStartTls = startTlsStatus === 'negotiated' || startTlsStatus === 'offered';

    let tlsInfo: TlsInfo | null = null;
    let cert: CertificateInfo | null = null;
    const sessionFindings: SecurityFinding[] = [];

    if (hasTls && tlsVersion && cipherSuite) {
      const tlsResult = analyzeTlsConfig(tlsVersion, cipherSuite, policy, protocol, stream.srcIp, stream.dstIp, sessionId, timestamp);
      tlsInfo = tlsResult.tls;
      sessionFindings.push(...tlsResult.findings);
    }

    // Generate synthetic certificate info when TLS is present but cert data not extractable from PCAP
    if (hasTls && !cert) {
      cert = generatePlaceholderCert(stream.dstIp, protocol);
    }

    if (cert) {
      const certFindings = analyzeCertificate(cert, policy, protocol, stream.srcIp, stream.dstIp, sessionId, timestamp);
      sessionFindings.push(...certFindings);
    }

    const startTlsFindings = analyzeStartTls(startTlsStatus, protocol, stream.srcIp, stream.dstIp, sessionId, timestamp, policy);
    sessionFindings.push(...startTlsFindings);

    findings.push(...sessionFindings);

    const riskScore = computeSessionRisk(sessionFindings, hasTls);
    const riskLevel = computeSessionRiskLevel(riskScore);

    sessions.push({
      id: sessionId,
      timestamp,
      protocol,
      sourceIp: stream.srcIp,
      destinationIp: stream.dstIp,
      sourcePort: stream.srcPort,
      destinationPort: stream.dstPort,
      sessionDuration: Math.round(duration * 10) / 10,
      hasTls,
      isStartTls,
      startTlsStatus,
      tls: tlsInfo,
      certificate: cert,
      packetCount: stream.packets.length,
      riskScore,
      riskLevel,
      confidence: hasTls ? 'confirmed' : startTlsStatus === 'plaintext' ? 'confirmed' : 'possible',
      findingIds: sessionFindings.map(f => f.id),
    });
  }

  const prioritizedFindings = applyAiPrioritization(findings, sessions);

  const updatedSessions = sessions.map(s => ({
    ...s,
    findingIds: prioritizedFindings.filter(f => f.sessionId === s.id).map(f => f.id),
  }));

  const score = calculateSecurityScore(updatedSessions, prioritizedFindings, policy);

  return buildAnalysisResult(fileName, fileSize, false, updatedSessions, prioritizedFindings, score);
}

function computeSessionRisk(findings: SecurityFinding[], hasTls: boolean): number {
  let score = hasTls ? 80 : 40;
  for (const f of findings) {
    switch (f.severity) {
      case 'critical': score -= 40; break;
      case 'high': score -= 20; break;
      case 'medium': score -= 10; break;
      case 'low': score -= 5; break;
    }
  }
  return Math.max(0, Math.min(100, score));
}

function computeSessionRiskLevel(score: number): EmailSession['riskLevel'] {
  if (score < 30) return 'critical';
  if (score < 50) return 'high';
  if (score < 70) return 'medium';
  if (score < 90) return 'low';
  return 'informational';
}

function generatePlaceholderCert(destIp: string, _protocol: EmailProtocol): CertificateInfo {
  return {
    subject: `unknown-${destIp}`,
    issuer: 'Insufficient data from PCAP',
    serialNumber: 'N/A',
    validFrom: 'N/A',
    validUntil: 'N/A',
    signatureAlgorithm: 'Unknown',
    publicKeyAlgorithm: 'Unknown',
    publicKeySize: 0,
    sanEntries: [],
    chainDepth: null,
    selfSigned: false,
    status: 'insufficient-data',
    statusDetail: 'Certificate details could not be extracted from the PCAP. The TLS handshake was observed but certificate data was not available in the capture.',
  };
}

export function loadDemoAnalysis(): AnalysisResult {
  return createDemoAnalysis();
}

export { type SecurityPolicy };
