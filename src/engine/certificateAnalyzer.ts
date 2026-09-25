import type { CertificateInfo, CertStatus, SecurityPolicy, SecurityFinding, EmailProtocol } from '@/types';

export function analyzeCertificate(
  cert: CertificateInfo,
  policy: SecurityPolicy,
  protocol: EmailProtocol,
  source: string,
  destination: string,
  sessionId: string,
  timestamp: string,
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const now = new Date();
  const validFrom = new Date(cert.validFrom);
  const validUntil = new Date(cert.validUntil);

  if (now < validFrom) {
    findings.push({
      id: `F-${sessionId}-NOTYETVALID`,
      severity: 'high',
      category: 'Certificate Validity',
      title: 'Certificate Not Yet Valid',
      protocol, source, destination,
      evidence: `Certificate valid-from date (${cert.validFrom}) is in the future.`,
      explanation: 'The certificate\'s validity period has not started yet. This indicates a clock skew or misconfigured certificate deployment.',
      impact: 'Clients should reject this certificate, causing TLS handshake failures and disrupting email delivery.',
      remediation: 'Verify system clocks are synchronized (NTP) and check the certificate deployment timeline.',
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'high', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (now > validUntil) {
    findings.push({
      id: `F-${sessionId}-EXPIRED`,
      severity: 'high',
      category: 'Certificate Validity',
      title: 'Expired Certificate',
      protocol, source, destination,
      evidence: `Certificate expired on ${cert.validUntil}. Current date is ${now.toISOString().split('T')[0]}.`,
      explanation: 'The certificate has passed its validity period. Expired certificates are rejected by modern email clients and servers.',
      impact: 'Expired certificates cause TLS failures, mail delivery disruptions, and may prevent STARTTLS from being negotiated.',
      remediation: 'Renew the certificate before expiration and implement monitoring for certificate expiry.',
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'high', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  const validityDays = (validUntil.getTime() - validFrom.getTime()) / (1000 * 60 * 60 * 24);
  if (validityDays > policy.maxCertValidityDays) {
    findings.push({
      id: `F-${sessionId}-LONGVALIDITY`,
      severity: 'low',
      category: 'Certificate Validity',
      title: 'Excessively Long Certificate Validity',
      protocol, source, destination,
      evidence: `Certificate validity period is ${Math.round(validityDays)} days (policy max: ${policy.maxCertValidityDays} days).`,
      explanation: 'The certificate has a validity period exceeding the policy maximum, reducing the window for key rotation and increasing exposure if compromised.',
      impact: 'Long-lived certificates increase the risk window if the private key is compromised.',
      remediation: 'Use shorter certificate lifetimes aligned with organizational policy.',
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'low', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  const sigAlgLower = cert.signatureAlgorithm.toLowerCase();
  if (policy.weakSignatureAlgorithms.some(a => sigAlgLower.includes(a))) {
    findings.push({
      id: `F-${sessionId}-WEAKSIG`,
      severity: 'medium',
      category: 'Certificate Signature',
      title: `Weak Signature Algorithm: ${cert.signatureAlgorithm}`,
      protocol, source, destination,
      evidence: `Certificate signed with ${cert.signatureAlgorithm}.`,
      explanation: `${cert.signatureAlgorithm} is considered a weak signature algorithm. SHA-1 and MD5 are deprecated due to known collision vulnerabilities.`,
      impact: 'Weak signature algorithms may allow certificate forgery, undermining the trust model of TLS.',
      remediation: 'Reissue the certificate using SHA-256 or stronger signature algorithms.',
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'medium', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (cert.publicKeyAlgorithm === 'RSA' && cert.publicKeySize < policy.minRsaKeySize) {
    findings.push({
      id: `F-${sessionId}-WEAKKEY`,
      severity: 'medium',
      category: 'Certificate Key',
      title: `Weak Public Key: ${cert.publicKeySize}-bit RSA`,
      protocol, source, destination,
      evidence: `Certificate uses ${cert.publicKeySize}-bit RSA key (policy minimum: ${policy.minRsaKeySize} bits).`,
      explanation: `RSA keys smaller than ${policy.minRsaKeySize} bits are considered weak by current standards and may be factored by determined attackers.`,
      impact: 'Weak keys can be compromised, allowing traffic decryption and impersonation.',
      remediation: `Reissue the certificate with at least ${policy.minRsaKeySize}-bit RSA or use ECDSA keys.`,
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'medium', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (cert.publicKeyAlgorithm === 'ECDSA' && cert.publicKeySize < policy.minEccKeySize) {
    findings.push({
      id: `F-${sessionId}-WEAKECCKEY`,
      severity: 'medium',
      category: 'Certificate Key',
      title: `Weak Public Key: ${cert.publicKeySize}-bit ECDSA`,
      protocol, source, destination,
      evidence: `Certificate uses ${cert.publicKeySize}-bit ECDSA key (policy minimum: ${policy.minEccKeySize} bits).`,
      explanation: `ECDSA keys smaller than ${policy.minEccKeySize} bits do not meet the policy minimum.`,
      impact: 'Weak keys may be vulnerable to cryptanalysis.',
      remediation: `Reissue with at least ${policy.minEccKeySize}-bit ECDSA keys.`,
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'medium', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (cert.selfSigned) {
    findings.push({
      id: `F-${sessionId}-SELFSIGNED`,
      severity: 'medium',
      category: 'Certificate Trust',
      title: 'Self-Signed Certificate',
      protocol, source, destination,
      evidence: `Certificate subject and issuer are identical ("${cert.subject}").`,
      explanation: 'Self-signed certificates are not signed by a trusted Certificate Authority. They provide encryption but no third-party identity verification.',
      impact: 'Clients may reject self-signed certificates, and they do not protect against man-in-the-middle attacks without manual trust configuration.',
      remediation: 'Use certificates from a trusted CA (internal or public) for production email servers.',
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'medium', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (cert.chainDepth !== null && cert.chainDepth < 2 && !cert.selfSigned) {
    findings.push({
      id: `F-${sessionId}-SHORTCHAIN`,
      severity: 'low',
      category: 'Certificate Chain',
      title: 'Incomplete or Short Certificate Chain',
      protocol, source, destination,
      evidence: `Certificate chain depth is ${cert.chainDepth}. A complete chain typically includes at least leaf + intermediate + root.`,
      explanation: 'A short certificate chain may indicate the server is not sending intermediate certificates, which can cause verification failures on clients.',
      impact: 'Clients without the intermediate certificate cached may fail to verify the server certificate.',
      remediation: 'Configure the server to send the full certificate chain including all intermediate certificates.',
      confidence: 'possible',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'low', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (cert.status === 'hostname-mismatch') {
    findings.push({
      id: `F-${sessionId}-HOSTMISMATCH`,
      severity: 'high',
      category: 'Certificate Hostname',
      title: 'Certificate Hostname Mismatch',
      protocol, source, destination,
      evidence: `The destination host does not match any SAN entry in the certificate.`,
      explanation: 'The certificate was issued for a different hostname than the one being accessed, which breaks TLS identity verification.',
      impact: 'Clients should reject this connection, causing TLS failures and mail delivery disruptions.',
      remediation: 'Reissue the certificate with the correct hostname in the SAN entries.',
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'high', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  return findings;
}

export function determineCertStatus(
  validFrom: string,
  validUntil: string,
  signatureAlgorithm: string,
  publicKeyAlgorithm: string,
  publicKeySize: number,
  selfSigned: boolean,
  sanEntries: string[],
  destinationHost: string | null,
): { status: CertStatus; statusDetail: string } {
  const now = new Date();
  const from = new Date(validFrom);
  const until = new Date(validUntil);

  if (now < from) return { status: 'not-yet-valid', statusDetail: 'Certificate validity period has not started.' };
  if (now > until) return { status: 'expired', statusDetail: `Certificate expired on ${validUntil}.` };

  const sigLower = signatureAlgorithm.toLowerCase();
  if (sigLower.includes('md5') || sigLower.includes('sha1') || sigLower.includes('md2')) {
    return { status: 'weak-signature', statusDetail: `Uses deprecated signature algorithm: ${signatureAlgorithm}.` };
  }

  if (publicKeyAlgorithm === 'RSA' && publicKeySize < 2048) {
    return { status: 'weak-key', statusDetail: `RSA key size ${publicKeySize} bits is below the 2048-bit minimum.` };
  }

  if (destinationHost && sanEntries.length > 0) {
    const hostMatch = sanEntries.some(san => san === destinationHost || san.includes(destinationHost));
    if (!hostMatch) {
      return { status: 'hostname-mismatch', statusDetail: `Destination host "${destinationHost}" not found in SAN entries.` };
    }
  }

  return { status: 'valid', statusDetail: 'Certificate is valid and meets current policy requirements.' };
}
