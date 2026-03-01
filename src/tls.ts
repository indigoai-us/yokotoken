/**
 * TLS module for hq-vault server.
 *
 * Generates self-signed certificates for HTTPS on localhost.
 * Certificates are auto-generated on first `hq-vault serve` and stored
 * in ~/.hq-vault/ for reuse.
 *
 * Uses Node.js built-in crypto for key generation and self-signed
 * certificate creation via the X509Certificate API.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface TlsCertPaths {
  certFile: string;
  keyFile: string;
}

export interface TlsCertData {
  cert: string;   // PEM-encoded certificate
  key: string;    // PEM-encoded private key
}

/**
 * Get the default certificate file paths.
 */
export function getDefaultCertPaths(): TlsCertPaths {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const vaultDir = path.join(home, '.hq-vault');
  return {
    certFile: path.join(vaultDir, 'server.crt'),
    keyFile: path.join(vaultDir, 'server.key'),
  };
}

/**
 * Check if TLS certificates already exist.
 */
export function certsExist(paths: TlsCertPaths): boolean {
  return fs.existsSync(paths.certFile) && fs.existsSync(paths.keyFile);
}

/**
 * Generate a self-signed certificate for localhost.
 *
 * The certificate is valid for 365 days and covers:
 * - CN=localhost
 * - SAN: DNS:localhost, IP:127.0.0.1, IP:::1
 */
export function generateSelfSignedCert(): TlsCertData {
  // Generate RSA key pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Create self-signed certificate using X509Certificate
  // Node.js 20+ has crypto.X509Certificate but not cert creation directly.
  // We'll create the cert using the lower-level createSign API with ASN.1.
  const cert = createSelfSignedCert(publicKey, privateKey);

  return { cert, key: privateKey as string };
}

/**
 * Create a minimal self-signed X.509 certificate.
 *
 * This builds the certificate structure manually since Node.js doesn't
 * have a built-in cert signing API. The certificate includes:
 * - Subject: CN=localhost
 * - Issuer: CN=localhost (self-signed)
 * - Validity: 365 days
 * - Subject Alternative Names: DNS:localhost, IP:127.0.0.1
 */
function createSelfSignedCert(publicKeyPem: string, privateKeyPem: string): string {
  // Extract the raw public key bytes from PEM
  const pubKeyDer = pemToDer(publicKeyPem, 'PUBLIC KEY');

  const now = new Date();
  const notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  // Build TBS (To-Be-Signed) certificate
  const serialNumber = crypto.randomBytes(8);
  // Ensure serial number is positive (set high bit to 0)
  serialNumber[0] = serialNumber[0] & 0x7f;

  const tbsCert = buildTBSCertificate({
    serialNumber,
    issuerCN: 'hq-vault',
    subjectCN: 'localhost',
    notBefore: now,
    notAfter,
    publicKeyDer: pubKeyDer,
  });

  // Sign the TBS certificate
  const signer = crypto.createSign('SHA256');
  signer.update(tbsCert);
  const signature = signer.sign(privateKeyPem);

  // Build the full certificate
  const cert = buildCertificate(tbsCert, signature);

  // Encode as PEM
  return derToPem(cert, 'CERTIFICATE');
}

// ─── ASN.1 DER encoding helpers ──────────────────────────────────────

function encodeLength(length: number): Buffer {
  if (length < 0x80) {
    return Buffer.from([length]);
  } else if (length < 0x100) {
    return Buffer.from([0x81, length]);
  } else if (length < 0x10000) {
    return Buffer.from([0x82, (length >> 8) & 0xff, length & 0xff]);
  } else {
    return Buffer.from([0x83, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff]);
  }
}

function encodeSequence(...items: Buffer[]): Buffer {
  const content = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), encodeLength(content.length), content]);
}

function encodeSet(...items: Buffer[]): Buffer {
  const content = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x31]), encodeLength(content.length), content]);
}

function encodeOID(oid: number[]): Buffer {
  // Encode the first two components specially
  const first = oid[0] * 40 + oid[1];
  const bytes: number[] = [first];

  for (let i = 2; i < oid.length; i++) {
    let val = oid[i];
    if (val < 128) {
      bytes.push(val);
    } else {
      const encoded: number[] = [];
      encoded.push(val & 0x7f);
      val >>= 7;
      while (val > 0) {
        encoded.push(0x80 | (val & 0x7f));
        val >>= 7;
      }
      encoded.reverse();
      bytes.push(...encoded);
    }
  }

  const content = Buffer.from(bytes);
  return Buffer.concat([Buffer.from([0x06]), encodeLength(content.length), content]);
}

function encodeUTF8String(str: string): Buffer {
  const content = Buffer.from(str, 'utf-8');
  return Buffer.concat([Buffer.from([0x0c]), encodeLength(content.length), content]);
}

function encodeInteger(value: Buffer): Buffer {
  // Ensure the integer is positive (prepend 0x00 if high bit is set)
  let content = value;
  if (value.length > 0 && (value[0] & 0x80) !== 0) {
    content = Buffer.concat([Buffer.from([0x00]), value]);
  }
  return Buffer.concat([Buffer.from([0x02]), encodeLength(content.length), content]);
}

function encodeBitString(data: Buffer): Buffer {
  // Prepend a 0x00 byte indicating 0 unused bits
  const content = Buffer.concat([Buffer.from([0x00]), data]);
  return Buffer.concat([Buffer.from([0x03]), encodeLength(content.length), content]);
}

function encodeUTCTime(date: Date): Buffer {
  const year = date.getUTCFullYear();
  let str: string;
  if (year >= 2000 && year < 2050) {
    // Use UTCTime (YYMMDDHHmmssZ)
    str = (year % 100).toString().padStart(2, '0') +
      (date.getUTCMonth() + 1).toString().padStart(2, '0') +
      date.getUTCDate().toString().padStart(2, '0') +
      date.getUTCHours().toString().padStart(2, '0') +
      date.getUTCMinutes().toString().padStart(2, '0') +
      date.getUTCSeconds().toString().padStart(2, '0') + 'Z';
    const content = Buffer.from(str, 'ascii');
    return Buffer.concat([Buffer.from([0x17]), encodeLength(content.length), content]);
  } else {
    // Use GeneralizedTime (YYYYMMDDHHmmssZ)
    str = year.toString().padStart(4, '0') +
      (date.getUTCMonth() + 1).toString().padStart(2, '0') +
      date.getUTCDate().toString().padStart(2, '0') +
      date.getUTCHours().toString().padStart(2, '0') +
      date.getUTCMinutes().toString().padStart(2, '0') +
      date.getUTCSeconds().toString().padStart(2, '0') + 'Z';
    const content = Buffer.from(str, 'ascii');
    return Buffer.concat([Buffer.from([0x18]), encodeLength(content.length), content]);
  }
}

function encodeExplicit(tag: number, content: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0xa0 | tag]),
    encodeLength(content.length),
    content,
  ]);
}

function encodeOctetString(data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x04]), encodeLength(data.length), data]);
}

// ─── Certificate construction ────────────────────────────────────────

// OIDs
const OID_SHA256_RSA = [1, 2, 840, 113549, 1, 1, 11];  // sha256WithRSAEncryption
const OID_COMMON_NAME = [2, 5, 4, 3];                     // commonName
const OID_SUBJECT_ALT_NAME = [2, 5, 29, 17];              // subjectAltName

interface TBSCertParams {
  serialNumber: Buffer;
  issuerCN: string;
  subjectCN: string;
  notBefore: Date;
  notAfter: Date;
  publicKeyDer: Buffer;
}

function buildTBSCertificate(params: TBSCertParams): Buffer {
  // Version: v3 (2)
  const version = encodeExplicit(0, encodeInteger(Buffer.from([2])));

  // Serial number
  const serial = encodeInteger(params.serialNumber);

  // Signature algorithm: SHA256withRSA
  const signAlg = encodeSequence(
    encodeOID(OID_SHA256_RSA),
    Buffer.from([0x05, 0x00]), // NULL
  );

  // Issuer: CN=hq-vault
  const issuer = encodeSequence(
    encodeSet(
      encodeSequence(encodeOID(OID_COMMON_NAME), encodeUTF8String(params.issuerCN)),
    ),
  );

  // Validity
  const validity = encodeSequence(
    encodeUTCTime(params.notBefore),
    encodeUTCTime(params.notAfter),
  );

  // Subject: CN=localhost
  const subject = encodeSequence(
    encodeSet(
      encodeSequence(encodeOID(OID_COMMON_NAME), encodeUTF8String(params.subjectCN)),
    ),
  );

  // Subject Public Key Info (reuse the raw DER from the key pair)
  const subjectPublicKeyInfo = params.publicKeyDer;

  // Extensions (v3): Subject Alternative Name
  const sanExtValue = buildSANExtension();
  const extensions = encodeExplicit(3, encodeSequence(
    encodeSequence(
      encodeOID(OID_SUBJECT_ALT_NAME),
      encodeOctetString(sanExtValue),
    ),
  ));

  return encodeSequence(
    version,
    serial,
    signAlg,
    issuer,
    validity,
    subject,
    subjectPublicKeyInfo,
    extensions,
  );
}

/**
 * Build Subject Alternative Name extension value.
 * Contains: DNS:localhost, IP:127.0.0.1, IP:::1
 */
function buildSANExtension(): Buffer {
  // DNS name (tag 2)
  const dnsName = Buffer.from('localhost', 'ascii');
  const dnsEntry = Buffer.concat([
    Buffer.from([0x82]), // context-specific tag 2 (dNSName)
    encodeLength(dnsName.length),
    dnsName,
  ]);

  // IPv4 address (tag 7): 127.0.0.1
  const ipv4 = Buffer.from([127, 0, 0, 1]);
  const ipv4Entry = Buffer.concat([
    Buffer.from([0x87]), // context-specific tag 7 (iPAddress)
    encodeLength(ipv4.length),
    ipv4,
  ]);

  // IPv6 address (tag 7): ::1
  const ipv6 = Buffer.alloc(16);
  ipv6[15] = 1; // ::1
  const ipv6Entry = Buffer.concat([
    Buffer.from([0x87]),
    encodeLength(ipv6.length),
    ipv6,
  ]);

  return encodeSequence(dnsEntry, ipv4Entry, ipv6Entry);
}

function buildCertificate(tbsCert: Buffer, signature: Buffer): Buffer {
  // Signature algorithm: SHA256withRSA
  const signAlg = encodeSequence(
    encodeOID(OID_SHA256_RSA),
    Buffer.from([0x05, 0x00]),
  );

  return encodeSequence(
    tbsCert,
    signAlg,
    encodeBitString(signature),
  );
}

// ─── PEM helpers ─────────────────────────────────────────────────────

function pemToDer(pem: string, label: string): Buffer {
  const lines = pem.split('\n');
  const base64 = lines
    .filter(line => !line.startsWith(`-----BEGIN ${label}`) && !line.startsWith(`-----END ${label}`) && line.trim().length > 0)
    .join('');
  return Buffer.from(base64, 'base64');
}

function derToPem(der: Buffer, label: string): string {
  const b64 = der.toString('base64');
  const lines: string[] = [`-----BEGIN ${label}-----`];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  lines.push(`-----END ${label}-----`);
  return lines.join('\n') + '\n';
}

// ─── High-level API ──────────────────────────────────────────────────

/**
 * Ensure TLS certificates exist. If not, generate new self-signed certs.
 * Returns the certificate data for use by the HTTPS server.
 */
export function ensureCerts(certPaths?: TlsCertPaths): TlsCertData {
  const paths = certPaths || getDefaultCertPaths();

  if (certsExist(paths)) {
    return {
      cert: fs.readFileSync(paths.certFile, 'utf-8'),
      key: fs.readFileSync(paths.keyFile, 'utf-8'),
    };
  }

  // Generate new self-signed certificates
  const certData = generateSelfSignedCert();

  // Ensure directory exists
  const dir = path.dirname(paths.certFile);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Write with restrictive permissions
  fs.writeFileSync(paths.certFile, certData.cert, { encoding: 'utf-8', mode: 0o644 });
  fs.writeFileSync(paths.keyFile, certData.key, { encoding: 'utf-8', mode: 0o600 });

  return certData;
}
