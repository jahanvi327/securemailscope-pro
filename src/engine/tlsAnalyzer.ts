import type { TlsInfo, TlsVersion, SecurityPolicy, SecurityFinding, EmailProtocol } from '@/types';

export function analyzeTlsConfig(
  version: TlsVersion,
  cipherSuite: string,
  policy: SecurityPolicy,
  protocol: EmailProtocol,
  source: string,
  destination: string,
  sessionId: string,
  timestamp: string,
): { tls: TlsInfo; findings: SecurityFinding[] } {
  const tls = parseCipherSuite(cipherSuite, version);
  const findings: SecurityFinding[] = [];

  if (policy.deprecatedTlsVersions.includes(version)) {
    findings.push({
      id: `F-${sessionId}-DEPTLS`,
      severity: 'high',
      category: 'TLS Version',
      title: `Deprecated TLS Version: ${version}`,
      protocol,
      source,
      destination,
      evidence: `Observed ${version} during ${protocol} session.`,
      explanation: `${version} is listed as deprecated in the current security policy. Older TLS versions have known vulnerabilities and weaker security guarantees.`,
      impact: 'Older TLS versions may violate organizational security policy and are vulnerable to known attacks (e.g., BEAST, POODLE, downgrade attacks).',
      remediation: 'Configure the mail service to support modern TLS versions (TLS 1.2 or 1.3) and disable deprecated protocols where operationally appropriate.',
      confidence: 'confirmed',
      sessionId,
      timestamp,
      aiPriority: 0, aiRiskLevel: 'high', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  const cipherUpper = cipherSuite.toUpperCase();
  const isWeak = policy.weakCipherSuites.some(w => cipherUpper.includes(w));
  if (isWeak) {
    const isCritical = /NULL|ANON|EXPORT|RC4|DES|MD5/.test(cipherUpper);
    findings.push({
      id: `F-${sessionId}-WEAKCIPHER`,
      severity: isCritical ? 'critical' : 'medium',
      category: 'Cipher Suite',
      title: `Weak Cipher Suite: ${cipherSuite}`,
      protocol,
      source,
      destination,
      evidence: `Observed cipher suite "${cipherSuite}" in ${protocol} session.`,
      explanation: 'This cipher suite uses algorithms considered weak or deprecated by current cryptographic standards.',
      impact: 'Weak cipher suites may be vulnerable to cryptanalysis or may not provide adequate confidentiality for sensitive email communications.',
      remediation: 'Configure the mail server to prefer modern cipher suites with AEAD encryption (GCM, ChaCha20-Poly1305) and forward secrecy (ECDHE).',
      confidence: 'confirmed',
      sessionId,
      timestamp,
      aiPriority: 0, aiRiskLevel: isCritical ? 'critical' : 'medium', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  if (policy.requireForwardSecrecy && tls.forwardSecrecy === false) {
    findings.push({
      id: `F-${sessionId}-NOFS`,
      severity: 'medium',
      category: 'Forward Secrecy',
      title: 'Forward Secrecy Not Provided',
      protocol,
      source,
      destination,
      evidence: `Cipher suite "${cipherSuite}" does not provide forward secrecy.`,
      explanation: 'The security policy requires forward secrecy, but the observed cipher suite does not use an ephemeral key exchange.',
      impact: 'Without forward secrecy, compromising the server private key would allow decryption of all past recorded traffic.',
      remediation: 'Prefer cipher suites using ECDHE or DHE key exchange to ensure forward secrecy.',
      confidence: 'confirmed',
      sessionId,
      timestamp,
      aiPriority: 0, aiRiskLevel: 'medium', aiConfidence: 0, aiContributingFeatures: [], aiExplanation: '',
    });
  }

  return { tls, findings };
}

function parseCipherSuite(cipherSuite: string, version: TlsVersion): TlsInfo {
  const upper = cipherSuite.toUpperCase();
  const isDirectTls = false;

  let keyExchange: string | null = null;
  let encryption: string | null = null;
  let authentication: string | null = null;
  let mac: string | null = null;
  let forwardSecrecy: boolean | null = null;

  if (upper.includes('ECDHE')) {
    keyExchange = 'ECDHE';
    forwardSecrecy = true;
  } else if (upper.includes('DHE')) {
    keyExchange = 'DHE';
    forwardSecrecy = true;
  } else if (upper.includes('RSA')) {
    keyExchange = 'RSA';
    forwardSecrecy = false;
  }

  if (upper.includes('ECDSA')) authentication = 'ECDSA';
  else if (upper.includes('RSA')) authentication = 'RSA';
  else if (upper.includes('DSS')) authentication = 'DSS';

  if (upper.includes('GCM')) { encryption = upper.includes('AES_128') ? 'AES-128-GCM' : upper.includes('AES_256') ? 'AES-256-GCM' : 'AES-GCM'; mac = 'AEAD'; }
  else if (upper.includes('CHACHA20')) { encryption = 'ChaCha20-Poly1305'; mac = 'AEAD'; }
  else if (upper.includes('CCM')) { encryption = 'AES-CCM'; mac = 'AEAD'; }
  else if (upper.includes('CBC')) { encryption = upper.includes('AES_128') ? 'AES-128-CBC' : upper.includes('AES_256') ? 'AES-256-CBC' : 'AES-CBC'; mac = upper.includes('SHA256') ? 'SHA256' : upper.includes('SHA384') ? 'SHA384' : 'SHA1'; }
  else if (upper.includes('RC4')) { encryption = 'RC4'; mac = upper.includes('MD5') ? 'MD5' : 'SHA1'; }
  else if (upper.includes('3DES')) { encryption = '3DES-EDE-CBC'; mac = 'SHA1'; }
  else if (upper.includes('NULL')) { encryption = 'NULL'; mac = upper.includes('MD5') ? 'MD5' : 'SHA1'; }

  // TLS 1.3 ciphers
  if (version === 'TLS 1.3' || upper.startsWith('TLS_AES') || upper.startsWith('TLS_CHACHA')) {
    keyExchange = 'ECDHE';
    forwardSecrecy = true;
    if (upper.includes('AES_128')) encryption = 'AES-128-GCM';
    else if (upper.includes('AES_256')) encryption = 'AES-256-GCM';
    else if (upper.includes('CHACHA20')) encryption = 'ChaCha20-Poly1305';
    mac = 'AEAD';
  }

  return { version, cipherSuite, keyExchange, encryption, authentication, mac, forwardSecrecy, isDirectTls };
}
