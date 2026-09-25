import type { SecurityScore, SecurityScoreBreakdown, EmailSession, SecurityFinding, SecurityPolicy } from '@/types';

export function calculateSecurityScore(
  sessions: EmailSession[],
  findings: SecurityFinding[],
  policy: SecurityPolicy,
): SecurityScore {
  const breakdown = calculateBreakdown(sessions, findings, policy);
  const weights = policy.scoreWeights;

  const rawScore =
    breakdown.tlsConfiguration * (weights.tlsConfiguration / 100) +
    breakdown.certificateSecurity * (weights.certificateSecurity / 100) +
    breakdown.protocolSecurity * (weights.protocolSecurity / 100) +
    breakdown.encryptionCoverage * (weights.encryptionCoverage / 100) +
    breakdown.cryptographicStrength * (weights.cryptographicStrength / 100) +
    breakdown.configurationWeaknesses * (weights.configurationWeaknesses / 100);

  const overall = Math.round(Math.max(0, Math.min(100, rawScore)));

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;
  const informationalCount = findings.filter(f => f.severity === 'informational').length;

  const riskLevel = determineRiskLevel(overall, criticalCount, highCount);

  return {
    overall,
    riskLevel,
    breakdown,
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    informationalCount,
  };
}

function calculateBreakdown(sessions: EmailSession[], findings: SecurityFinding[], policy: SecurityPolicy): SecurityScoreBreakdown {
  if (sessions.length === 0) {
    return {
      tlsConfiguration: 100,
      certificateSecurity: 100,
      protocolSecurity: 100,
      encryptionCoverage: 100,
      cryptographicStrength: 100,
      configurationWeaknesses: 100,
    };
  }

  const tlsSessions = sessions.filter(s => s.hasTls);
  const tlsScore = calculateTlsScore(tlsSessions, policy);
  const certScore = calculateCertScore(sessions);
  const protocolScore = calculateProtocolScore(sessions, policy);
  const encryptionScore = calculateEncryptionScore(sessions);
  const cryptoScore = calculateCryptoScore(tlsSessions, policy);
  const weaknessScore = calculateWeaknessScore(findings);

  return {
    tlsConfiguration: tlsScore,
    certificateSecurity: certScore,
    protocolSecurity: protocolScore,
    encryptionCoverage: encryptionScore,
    cryptographicStrength: cryptoScore,
    configurationWeaknesses: weaknessScore,
  };
}

function calculateTlsScore(tlsSessions: EmailSession[], policy: SecurityPolicy): number {
  if (tlsSessions.length === 0) return 100;
  let score = 100;
  const deprecatedCount = tlsSessions.filter(s => s.tls && policy.deprecatedTlsVersions.includes(s.tls.version)).length;
  score -= (deprecatedCount / tlsSessions.length) * 60;
  return Math.round(Math.max(0, score));
}

function calculateCertScore(sessions: EmailSession[]): number {
  const certSessions = sessions.filter(s => s.certificate);
  if (certSessions.length === 0) return 100;
  let score = 100;
  for (const s of certSessions) {
    if (!s.certificate) continue;
    if (s.certificate.status === 'expired') score -= 15;
    else if (s.certificate.status === 'not-yet-valid') score -= 15;
    else if (s.certificate.status === 'weak-signature') score -= 8;
    else if (s.certificate.status === 'weak-key') score -= 8;
    else if (s.certificate.status === 'hostname-mismatch') score -= 12;
    else if (s.certificate.status === 'insufficient-data') score -= 2;
  }
  return Math.round(Math.max(0, Math.min(100, score)));
}

function calculateProtocolScore(sessions: EmailSession[], policy: SecurityPolicy): number {
  if (sessions.length === 0) return 100;
  let score = 100;
  const plaintextCount = sessions.filter(s => s.startTlsStatus === 'plaintext').length;
  score -= (plaintextCount / sessions.length) * 70;
  if (policy.requireStartTls) {
    const noTlsCount = sessions.filter(s => !s.hasTls).length;
    score -= (noTlsCount / sessions.length) * 30;
  }
  return Math.round(Math.max(0, score));
}

function calculateEncryptionScore(sessions: EmailSession[]): number {
  if (sessions.length === 0) return 100;
  const encryptedCount = sessions.filter(s => s.hasTls).length;
  return Math.round((encryptedCount / sessions.length) * 100);
}

function calculateCryptoScore(tlsSessions: EmailSession[], policy: SecurityPolicy): number {
  if (tlsSessions.length === 0) return 100;
  let score = 100;
  for (const s of tlsSessions) {
    if (!s.tls) continue;
    if (policy.weakCipherSuites.some(w => s.tls!.cipherSuite.toUpperCase().includes(w))) score -= 10;
    if (s.tls.forwardSecrecy === false && policy.requireForwardSecrecy) score -= 5;
  }
  return Math.round(Math.max(0, Math.min(100, score)));
}

function calculateWeaknessScore(findings: SecurityFinding[]): number {
  let penalty = 0;
  for (const f of findings) {
    switch (f.severity) {
      case 'critical': penalty += 8; break;
      case 'high': penalty += 5; break;
      case 'medium': penalty += 3; break;
      case 'low': penalty += 1; break;
    }
  }
  return Math.round(Math.max(0, 100 - penalty));
}

function determineRiskLevel(overall: number, criticalCount: number, highCount: number): SecurityScore['riskLevel'] {
  if (criticalCount > 0 || overall < 40) return 'critical';
  if (highCount >= 3 || overall < 60) return 'high';
  if (highCount >= 1 || overall < 75) return 'medium';
  if (overall < 90) return 'low';
  return 'informational';
}
