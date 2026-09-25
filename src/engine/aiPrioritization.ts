import type { SecurityFinding, Severity, EmailSession } from '@/types';

interface FeatureVector {
  severityWeight: number;
  confidenceWeight: number;
  protocolWeight: number;
  categoryWeight: number;
  isConfirmed: boolean;
  hasExpiredCert: boolean;
  hasDeprecatedTls: boolean;
  hasPlaintext: boolean;
  hasWeakCipher: boolean;
}

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 100,
  high: 75,
  medium: 50,
  low: 25,
  informational: 10,
};

const PROTOCOL_WEIGHTS: Record<string, number> = {
  SMTP: 1.0,
  IMAP: 0.9,
  POP3: 0.85,
  General: 0.5,
};

const CATEGORY_WEIGHTS: Record<string, number> = {
  'TLS Version': 1.2,
  'Cipher Suite': 1.1,
  'Certificate Validity': 1.15,
  'Certificate Signature': 1.0,
  'Certificate Key': 1.05,
  'Certificate Trust': 1.1,
  'Certificate Chain': 0.9,
  'Certificate Hostname': 1.15,
  'STARTTLS': 1.3,
  'Forward Secrecy': 0.95,
};

export function applyAiPrioritization(findings: SecurityFinding[], sessions: EmailSession[]): SecurityFinding[] {
  if (findings.length === 0) return findings;

  const sessionMap = new Map(sessions.map(s => [s.id, s]));

  const featureVectors = findings.map(f => extractFeatures(f, sessionMap.get(f.sessionId || '')));
  const priorities = predictPriorities(featureVectors);

  return findings.map((finding, i) => {
    const priority = priorities[i];
    const features = featureVectors[i];
    const aiRiskLevel = mapPriorityToSeverity(priority);
    const aiConfidence = calculateConfidence(features);
    const contributingFeatures = getContributingFeatures(features);
    const aiExplanation = generateExplanation(finding, features, priority);

    return {
      ...finding,
      aiPriority: priority,
      aiRiskLevel,
      aiConfidence,
      aiContributingFeatures: contributingFeatures,
      aiExplanation,
    };
  }).sort((a, b) => b.aiPriority - a.aiPriority);
}

function extractFeatures(finding: SecurityFinding, session?: EmailSession): FeatureVector {
  return {
    severityWeight: SEVERITY_WEIGHTS[finding.severity],
    confidenceWeight: finding.confidence === 'confirmed' ? 1.0 : finding.confidence === 'possible' ? 0.7 : 0.3,
    protocolWeight: PROTOCOL_WEIGHTS[finding.protocol] || 0.5,
    categoryWeight: CATEGORY_WEIGHTS[finding.category] || 1.0,
    isConfirmed: finding.confidence === 'confirmed',
    hasExpiredCert: finding.category.includes('Certificate') && finding.title.includes('Expired'),
    hasDeprecatedTls: finding.category === 'TLS Version' && finding.title.includes('Deprecated'),
    hasPlaintext: finding.category === 'STARTTLS' && finding.title.includes('Plaintext'),
    hasWeakCipher: finding.category === 'Cipher Suite',
  };
}

function predictPriorities(vectors: FeatureVector[]): number[] {
  const maxSeverity = Math.max(...vectors.map(v => v.severityWeight), 1);

  return vectors.map(v => {
    const baseScore = (v.severityWeight / maxSeverity) * 100;
    const confidenceFactor = 0.7 + v.confidenceWeight * 0.3;
    const protocolFactor = v.protocolWeight;
    const categoryFactor = v.categoryWeight;

    let score = baseScore * confidenceFactor * protocolFactor * categoryFactor;

    if (v.hasPlaintext) score *= 1.2;
    if (v.hasExpiredCert) score *= 1.1;
    if (v.hasDeprecatedTls) score *= 1.05;
    if (v.hasWeakCipher && v.isConfirmed) score *= 1.08;

    return Math.round(Math.min(100, Math.max(0, score)));
  });
}

function mapPriorityToSeverity(priority: number): Severity {
  if (priority >= 85) return 'critical';
  if (priority >= 65) return 'high';
  if (priority >= 40) return 'medium';
  if (priority >= 20) return 'low';
  return 'informational';
}

function calculateConfidence(features: FeatureVector): number {
  let conf = 0.5;
  if (features.isConfirmed) conf += 0.3;
  if (features.severityWeight >= 75) conf += 0.15;
  if (features.categoryWeight >= 1.1) conf += 0.05;
  return Math.round(Math.min(0.99, conf) * 100) / 100;
}

function getContributingFeatures(features: FeatureVector): string[] {
  const features_list: string[] = [];
  if (features.hasPlaintext) features_list.push('Plaintext session detected');
  if (features.hasExpiredCert) features_list.push('Expired certificate');
  if (features.hasDeprecatedTls) features_list.push('Deprecated TLS version');
  if (features.hasWeakCipher) features_list.push('Weak cipher suite');
  features_list.push(`Severity weight: ${features.severityWeight}`);
  features_list.push(`Confidence: ${features.confidenceWeight === 1.0 ? 'Confirmed' : features.confidenceWeight === 0.7 ? 'Possible' : 'Insufficient data'}`);
  features_list.push(`Protocol weight: ${features.protocolWeight.toFixed(2)}`);
  return features_list;
}

function generateExplanation(finding: SecurityFinding, features: FeatureVector, priority: number): string {
  const reasons: string[] = [];

  if (features.hasPlaintext) reasons.push('plaintext email transmission exposes credentials and content');
  if (features.hasExpiredCert) reasons.push('expired certificates disrupt TLS and mail delivery');
  if (features.hasDeprecatedTls) reasons.push('deprecated TLS versions have known vulnerabilities');
  if (features.hasWeakCipher) reasons.push('weak cipher suites provide inadequate encryption');

  if (reasons.length === 0) {
    reasons.push(`${finding.category.toLowerCase()} issue affecting ${finding.protocol} communications`);
  }

  const confidenceStr = features.isConfirmed ? 'high confidence' : features.confidenceWeight >= 0.7 ? 'moderate confidence' : 'low confidence';

  return `Priority ${priority}/100 — ${reasons.join(', ')}. Based on ${confidenceStr} deterministic analysis of extracted packet features.`;
}

export function groupSimilarFindings(findings: SecurityFinding[]): SecurityFinding[][] {
  const groups: SecurityFinding[][] = [];
  const assigned = new Set<string>();

  for (const finding of findings) {
    if (assigned.has(finding.id)) continue;
    const group = [finding];
    assigned.add(finding.id);

    for (const other of findings) {
      if (assigned.has(other.id)) continue;
      if (finding.category === other.category && finding.severity === other.severity && finding.protocol === other.protocol) {
        group.push(other);
        assigned.add(other.id);
      }
    }
    groups.push(group);
  }

  return groups;
}
