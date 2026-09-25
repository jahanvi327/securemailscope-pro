import type { EmailProtocol, TlsVersion, StartTlsStatus } from '@/types';

interface ParsedPacket {
  timestamp: number;
  data: Uint8Array;
}

export interface TcpStream {
  streamId: string;
  packets: ParsedPacket[];
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  payload: Uint8Array;
}

const PCAP_MAGIC_LE = 0xa1b2c3d4;
const PCAP_MAGIC_BE = 0xd4c3b2a1;
const PCAPNG_MAGIC_LE = 0x0a0d0d0a;

const EMAIL_PORTS: Record<EmailProtocol, number[]> = {
  SMTP: [25, 587, 465],
  IMAP: [143, 993],
  POP3: [110, 995],
};

function readUint32(data: Uint8Array, offset: number, littleEndian: boolean): number {
  const view = new DataView(data.buffer, data.byteOffset + offset, 4);
  return view.getUint32(0, littleEndian);
}

function readUint16(data: Uint8Array, offset: number, littleEndian: boolean): number {
  const view = new DataView(data.buffer, data.byteOffset + offset, 2);
  return view.getUint16(0, littleEndian);
}

function ipToString(bytes: number[]): string {
  return bytes.join('.');
}

export function detectProtocol(port: number): EmailProtocol | null {
  for (const [proto, ports] of Object.entries(EMAIL_PORTS)) {
    if (ports.includes(port)) return proto as EmailProtocol;
  }
  return null;
}

export interface PcapParseResult {
  valid: boolean;
  error?: string;
  isPcapng: boolean;
  packetCount: number;
  streams: TcpStream[];
  emailStreams: TcpStream[];
}

export function parsePcap(buffer: ArrayBuffer): PcapParseResult {
  if (buffer.byteLength < 24) {
    return { valid: false, error: 'File too small to be a valid PCAP file (minimum 24 bytes for global header).', isPcapng: false, packetCount: 0, streams: [], emailStreams: [] };
  }

  const bytes = new Uint8Array(buffer);
  const magicLE = readUint32(bytes, 0, true);
  const magicBE = readUint32(bytes, 0, false);

  let littleEndian: boolean;
  let isPcapng = false;

  if (magicLE === PCAP_MAGIC_LE) {
    littleEndian = true;
  } else if (magicBE === PCAP_MAGIC_LE) {
    littleEndian = false;
  } else if (magicLE === PCAPNG_MAGIC_LE || magicBE === PCAPNG_MAGIC_LE) {
    isPcapng = true;
    littleEndian = true;
  } else {
    return { valid: false, error: 'Unrecognized file format. Expected PCAP (magic 0xa1b2c3d4) or PCAPNG (0x0a0d0d0a).', isPcapng: false, packetCount: 0, streams: [], emailStreams: [] };
  }

  if (isPcapng) {
    return parsePcapng(bytes);
  }

  const network = readUint32(bytes, 20, littleEndian);
  if (network !== 1 && network !== 101) {
    return { valid: false, error: `Unsupported link-layer type ${network}. Only Ethernet (1) and raw IP (101) are supported.`, isPcapng: false, packetCount: 0, streams: [], emailStreams: [] };
  }

  const packets: ParsedPacket[] = [];
  let offset = 24;
  const snaplen = readUint32(bytes, 16, littleEndian);

  while (offset + 16 <= bytes.length) {
    const tsSec = readUint32(bytes, offset, littleEndian);
    const tsUsec = readUint32(bytes, offset + 4, littleEndian);
    const inclLen = readUint32(bytes, offset + 8, littleEndian);

    offset += 16;

    if (inclLen === 0 || inclLen > snaplen || offset + inclLen > bytes.length) break;

    const pktData = bytes.slice(offset, offset + inclLen);
    packets.push({ timestamp: tsSec + tsUsec / 1e6, data: pktData });
    offset += inclLen;
  }

  const streams = extractTcpStreams(packets, network);
  const emailStreams = streams.filter(s => detectProtocol(s.dstPort) || detectProtocol(s.srcPort));

  return { valid: true, isPcapng: false, packetCount: packets.length, streams, emailStreams };
}

function parsePcapng(bytes: Uint8Array): PcapParseResult {
  const packets: ParsedPacket[] = [];
  let offset = 0;
  let linkType = 1;

  while (offset + 8 <= bytes.length) {
    const blockType = readUint32(bytes, offset, true);
    const blockTotalLen = readUint32(bytes, offset + 4, true);

    if (blockTotalLen < 12 || offset + blockTotalLen > bytes.length) break;

    if (blockType === 0x00000001 && blockTotalLen >= 12) {
      // Section Header Block — detect endianness from byte order magic
      const bom = readUint32(bytes, offset + 8, true);
      if (bom === 0x4d3c2b1a) {
        // big endian — re-read block length
        // For simplicity, we support LE pcapng primarily
      }
    } else if (blockType === 0x00000001) {
      // Interface Description Block
      linkType = readUint16(bytes, offset + 8, true);
    } else if (blockType === 0x00000006) {
      // Enhanced Packet Block
      if (blockTotalLen >= 28) {
        const tsHigh = readUint32(bytes, offset + 12, true);
        const tsLow = readUint32(bytes, offset + 16, true);
        const inclLen = readUint32(bytes, offset + 20, true);
        if (inclLen > 0 && 28 + inclLen <= blockTotalLen) {
          const pktData = bytes.slice(offset + 28, offset + 28 + inclLen);
          const timestamp = (tsHigh * 4294967296 + tsLow) / 1e6;
          packets.push({ timestamp, data: pktData });
        }
      }
    } else if (blockType === 0x00000003) {
      // Simple Packet Block
      const inclLen = readUint32(bytes, offset + 8, true);
      if (inclLen > 0 && 12 + inclLen <= blockTotalLen) {
        const pktData = bytes.slice(offset + 12, offset + 12 + inclLen);
        packets.push({ timestamp: 0, data: pktData });
      }
    }

    offset += blockTotalLen;
  }

  const streams = extractTcpStreams(packets, linkType);
  const emailStreams = streams.filter(s => detectProtocol(s.dstPort) || detectProtocol(s.srcPort));

  return { valid: true, isPcapng: true, packetCount: packets.length, streams, emailStreams };
}

function extractTcpStreams(packets: ParsedPacket[], linkType: number): TcpStream[] {
  const streamMap = new Map<string, TcpStream>();

  for (const pkt of packets) {
    const tcpInfo = parseTcpFromPacket(pkt.data, linkType);
    if (!tcpInfo) continue;

    const streamKey = [tcpInfo.srcIp, tcpInfo.dstIp, tcpInfo.srcPort, tcpInfo.dstPort].sort().join(':');

    if (!streamMap.has(streamKey)) {
      streamMap.set(streamKey, {
        streamId: streamKey,
        packets: [],
        srcIp: tcpInfo.srcIp,
        dstIp: tcpInfo.dstIp,
        srcPort: tcpInfo.srcPort,
        dstPort: tcpInfo.dstPort,
        payload: new Uint8Array(),
      });
    }

    const stream = streamMap.get(streamKey)!;
    stream.packets.push(pkt);

    if (tcpInfo.payload && tcpInfo.payload.length > 0) {
      const newPayload = new Uint8Array(stream.payload.length + tcpInfo.payload.length);
      newPayload.set(stream.payload);
      newPayload.set(tcpInfo.payload, stream.payload.length);
      stream.payload = newPayload;
    }
  }

  return Array.from(streamMap.values());
}

interface TcpInfo {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  payload: Uint8Array | null;
}

function parseTcpFromPacket(data: Uint8Array, linkType: number): TcpInfo | null {
  let ipOffset = 0;
  let ipVersion = 4;

  if (linkType === 1) {
    if (data.length < 14) return null;
    let ethType = (data[12] << 8) | data[13];
    let headerLen = 14;

    if (ethType === 0x8100) {
      if (data.length < 18) return null;
      ethType = (data[16] << 8) | data[17];
      headerLen = 18;
    }

    if (ethType === 0x0800) {
      ipOffset = headerLen;
      ipVersion = 4;
    } else if (ethType === 0x86dd) {
      ipOffset = headerLen;
      ipVersion = 6;
    } else {
      return null;
    }
  } else if (linkType === 101) {
    if (data.length < 1) return null;
    ipVersion = (data[0] >> 4) & 0xf;
  } else {
    return null;
  }

  return ipVersion === 4 ? parseIpv4Tcp(data, ipOffset) : ipVersion === 6 ? parseIpv6Tcp(data, ipOffset) : null;
}

function parseIpv4Tcp(data: Uint8Array, offset: number): TcpInfo | null {
  if (data.length < offset + 20) return null;
  const ihl = (data[offset] & 0xf) * 4;
  if (ihl < 20 || data.length < offset + ihl) return null;
  if (data[offset + 9] !== 6) return null; // TCP

  const srcIp = ipToString([data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]]);
  const dstIp = ipToString([data[offset + 16], data[offset + 17], data[offset + 18], data[offset + 19]]);

  return parseTcp(data, offset + ihl, srcIp, dstIp);
}

function parseIpv6Tcp(data: Uint8Array, offset: number): TcpInfo | null {
  if (data.length < offset + 40) return null;
  if (data[offset + 6] !== 6) return null; // TCP

  const srcIp = ipv6ToString(data, offset + 8);
  const dstIp = ipv6ToString(data, offset + 24);

  return parseTcp(data, offset + 40, srcIp, dstIp);
}

function ipv6ToString(data: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) {
    parts.push(((data[offset + i * 2] << 8) | data[offset + i * 2 + 1]).toString(16));
  }
  return parts.join(':');
}

function parseTcp(data: Uint8Array, offset: number, srcIp: string, dstIp: string): TcpInfo | null {
  if (data.length < offset + 20) return null;
  const srcPort = (data[offset] << 8) | data[offset + 1];
  const dstPort = (data[offset + 2] << 8) | data[offset + 3];
  const dataOffset = ((data[offset + 12] >> 4) & 0xf) * 4;
  const flags = data[offset + 13];

  const payloadStart = offset + dataOffset;
  let payload: Uint8Array | null = null;
  if (payloadStart < data.length && (flags & 0x18) !== 0) {
    payload = data.slice(payloadStart);
  }

  return { srcIp, dstIp, srcPort, dstPort, payload };
}

export function detectStartTlsFromPayload(payload: Uint8Array): StartTlsStatus {
  if (payload.length === 0) return 'not-observed';
  const text = new TextDecoder('utf-8', { fatal: false }).decode(payload.slice(0, Math.min(payload.length, 8192)));

  if (/STARTTLS/i.test(text)) {
    if (/220\s+Ready|220\s+Go\s+ahead|OK\s+BEGIN\s+TLS/i.test(text)) return 'negotiated';
    return 'offered';
  }

  if (/^(EHLO|HELO|MAIL\s+FROM|RCPT\s+TO|AUTH|LOGIN|SELECT|FETCH|LIST|RETR|STAT|CAPA|USER|PASS)/im.test(text)) {
    return 'plaintext';
  }

  return 'not-observed';
}

export function detectTlsVersionFromPayload(payload: Uint8Array): TlsVersion | null {
  if (payload.length < 6) return null;
  const contentType = payload[0];
  if (contentType !== 0x16 && contentType !== 0x14 && contentType !== 0x15) return null;

  const major = payload[1];
  const minor = payload[2];

  if (major === 0x03 && minor === 0x01) return 'TLS 1.0';
  if (major === 0x03 && minor === 0x02) return 'TLS 1.1';
  if (major === 0x03 && minor === 0x03) {
    if (contentType === 0x16 && payload.length > 43 && payload[5] === 0x01) {
      return detectTls13FromClientHello(payload);
    }
    return 'TLS 1.2';
  }
  if (major === 0x03 && minor === 0x04) return 'TLS 1.3';

  return 'Unknown';
}

function detectTls13FromClientHello(payload: Uint8Array): TlsVersion {
  for (let i = 0; i < payload.length - 6; i++) {
    if (payload[i] === 0x00 && payload[i + 1] === 0x2b) {
      if (payload[i + 4] === 0x03 && payload[i + 5] === 0x04) return 'TLS 1.3';
    }
  }
  return 'TLS 1.2';
}

const CIPHER_MAP: Record<number, string> = {
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA', 0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256', 0x003d: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256', 0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0xc009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 0xc00a: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
  0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
  0x009e: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 0x009f: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
  0x0005: 'TLS_RSA_WITH_RC4_128_SHA', 0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 0xc011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
  0xc012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
  0x0000: 'TLS_RSA_WITH_NULL_SHA', 0x0001: 'TLS_RSA_WITH_NULL_MD5',
  0xc09c: 'TLS_RSA_WITH_AES_128_CCM', 0xc09d: 'TLS_RSA_WITH_AES_256_CCM',
  0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 0xc028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
  0xc023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 0xc024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
  0x0041: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA', 0x0042: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
  0x0044: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', 0x0045: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
  0x0067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 0x006b: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
  0x00a0: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', 0x00a1: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
};

export function extractCipherSuiteFromPayload(payload: Uint8Array): string | null {
  if (payload.length < 11 || payload[0] !== 0x16 || payload[5] !== 0x01) return null;
  if (payload.length < 43) return null;

  let offset = 43;
  if (offset >= payload.length) return null;
  const sessionIdLen = payload[offset];
  offset += 1 + sessionIdLen;

  if (offset + 2 > payload.length) return null;
  const cipherLen = (payload[offset] << 8) | payload[offset + 1];
  offset += 2;

  if (cipherLen === 0 || offset + cipherLen > payload.length) return null;

  const cipherCode = (payload[offset] << 8) | payload[offset + 1];
  return CIPHER_MAP[cipherCode] || `Unknown(0x${cipherCode.toString(16).padStart(4, '0')})`;
}
