import type { EmailProtocol, StartTlsStatus, SecurityFinding, SecurityPolicy } from '@/types';

export function analyzeStartTls(
  status: StartTlsStatus,
  protocol: EmailProtocol,
  source: string,
  destination: string,
  sessionId: string,
  timestamp: string,
  policy: SecurityPolicy,
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  if (status === 'plaintext') {
    findings.push({
      id: `F-${sessionId}-PLAINTEXT`,
      severity: 'critical',
      category: 'STARTTLS',
      title: `Plaintext ${protocol} Session Without Encryption`,
      protocol, source, destination,
      evidence: `Observed plaintext ${protocol} commands without STARTTLS negotiation or TLS.`,
      explanation: `The ${protocol} session is transmitting in plaintext. Email credentials, messages, and metadata are exposed on the network.`,
      impact: 'Plaintext email sessions expose credentials and message contents to anyone who can observe network traffic.',
      remediation: `Enable and require STARTTLS on the ${protocol} server. Configure clients to refuse plaintext fallback.`,
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'critical', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (status === 'offered' && policy.requireStartTls) {
    findings.push({
      id: `F-${sessionId}-STARTTLSOFFERED`,
      severity: 'low',
      category: 'STARTTLS',
      title: `${protocol} STARTTLS Offered But Not Negotiated`,
      protocol, source, destination,
      evidence: `Server offered STARTTLS but negotiation was not observed in the capture.`,
      explanation: 'The server supports STARTTLS, but the client did not complete the upgrade. This may be a client misconfiguration or the full handshake was outside the capture window.',
      impact: 'If STARTTLS is not negotiated, the session may continue in plaintext.',
      remediation: 'Configure clients to require STARTTLS and refuse plaintext fallback.',
      confidence: 'possible',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'low', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (status === 'failed') {
    findings.push({
      id: `F-${sessionId}-STARTTLSFAILED`,
      severity: 'high',
      category: 'STARTTLS',
      title: `${protocol} STARTTLS Negotiation Failed`,
      protocol, source, destination,
      evidence: `STARTTLS negotiation was initiated but failed or was aborted.`,
      explanation: 'The STARTTLS upgrade failed, possibly due to certificate errors, protocol mismatches, or configuration issues.',
      impact: 'Failed STARTTLS may cause the session to fall back to plaintext or abort, disrupting email delivery.',
      remediation: 'Investigate the STARTTLS failure cause. Check certificates, TLS versions, and client/server compatibility.',
      confidence: 'confirmed',
      sessionId, timestamp,
      aiPriority: 0, aiRiskLevel: 'high', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  return findings;
}
