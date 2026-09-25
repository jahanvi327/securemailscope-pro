export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type Confidence = 'confirmed' | 'possible' | 'insufficient-data';
export type EmailProtocol = 'SMTP' | 'IMAP' | 'POP3';
export type TlsVersion = 'TLS 1.0' | 'TLS 1.1' | 'TLS 1.2' | 'TLS 1.3' | 'Unknown';
export type StartTlsStatus = 'offered' | 'negotiated' | 'not-observed' | 'failed' | 'plaintext';
export type CertStatus = 'valid' | 'expired' | 'not-yet-valid' | 'weak-signature' | 'weak-key' | 'hostname-mismatch' | 'insufficient-data';

export interface TlsInfo {
  version: TlsVersion;
  cipherSuite: string;
  keyExchange: string | null;
  encryption: string | null;
  authentication: string | null;
  mac: string | null;
  forwardSecrecy: boolean | null;
  isDirectTls: boolean;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validUntil: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeySize: number;
  sanEntries: string[];
  chainDepth: number | null;
  selfSigned: boolean;
  status: CertStatus;
  statusDetail: string;
}

export interface EmailSession {
  id: string;
  timestamp: string;
  protocol: EmailProtocol;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  sessionDuration: number;
  hasTls: boolean;
  isStartTls: boolean;
  startTlsStatus: StartTlsStatus;
  tls: TlsInfo | null;
  certificate: CertificateInfo | null;
  packetCount: number;
  riskScore: number;
  riskLevel: Severity;
  confidence: Confidence;
  findingIds: string[];
}

export interface SecurityFinding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  protocol: EmailProtocol | 'General';
  source: string;
  destination: string;
  evidence: string;
  explanation: string;
  impact: string;
  remediation: string;
  confidence: Confidence;
  sessionId: string | null;
  timestamp: string;
  aiPriority: number;
  aiRiskLevel: Severity;
  aiConfidence: number;
  aiContributingFeatures: string[];
  aiExplanation: string;
}

export interface SecurityScoreBreakdown {
  tlsConfiguration: number;
  certificateSecurity: number;
  protocolSecurity: number;
  encryptionCoverage: number;
  cryptographicStrength: number;
  configurationWeaknesses: number;
}

export interface SecurityScore {
  overall: number;
  riskLevel: Severity;
  breakdown: SecurityScoreBreakdown;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  informationalCount: number;
}

export interface AnalysisResult {
  id: string;
  fileName: string;
  fileSize: number;
  uploadedAt: string;
  isDemo: boolean;
  sessions: EmailSession[];
  findings: SecurityFinding[];
  score: SecurityScore;
  tlsVersionDistribution: { version: string; count: number; percentage: number }[];
  cipherDistribution: { cipher: string; count: number }[];
  certificateStatusDistribution: { status: string; count: number }[];
  findingsByProtocol: { protocol: string; count: number }[];
  findingsTimeline: { time: string; severity: Severity; count: number }[];
  topRiskyHosts: { host: string; riskScore: number; findingCount: number }[];
}

export interface SecurityPolicy {
  deprecatedTlsVersions: TlsVersion[];
  weakCipherSuites: string[];
  minRsaKeySize: number;
  minEccKeySize: number;
  weakSignatureAlgorithms: string[];
  requireForwardSecrecy: boolean;
  requireStartTls: boolean;
  maxCertValidityDays: number;
  scoreWeights: SecurityScoreBreakdown;
}
