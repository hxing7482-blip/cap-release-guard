import { createHash, X509Certificate } from 'node:crypto';
import { extname } from 'node:path';
import { readFile } from 'node:fs/promises';
import { normalizeFingerprint } from '../utils/hash.js';

export interface PublicCertificateInfo {
  subject: string;
  md5: string;
  sha1: string;
  sha256: string;
  spkiSha256: string;
  publicKeyAlgorithm: string;
  publicKeySize?: number;
  rsaModulusDecimal?: string;
  rsaModulusHex?: string;
}

function hash(raw: Buffer, algorithm: 'md5' | 'sha1' | 'sha256'): string {
  return createHash(algorithm).update(raw).digest('hex').toUpperCase();
}

function base64UrlToBuffer(value: string): Buffer {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  return Buffer.from(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='), 'base64');
}

export function parsePublicCertificate(data: Buffer | string): PublicCertificateInfo {
  const text = typeof data === 'string' ? data : data.toString('utf8');
  if (/BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY/i.test(text)) {
    throw new Error('Private key input is not accepted.');
  }
  const certificate = new X509Certificate(data);
  const spki = certificate.publicKey.export({ type: 'spki', format: 'der' });
  const algorithm = certificate.publicKey.asymmetricKeyType?.toUpperCase() ?? 'UNKNOWN';
  const details = certificate.publicKey.asymmetricKeyDetails;
  const publicKeySize = details && 'modulusLength' in details ? details.modulusLength : undefined;

  let rsaModulusDecimal: string | undefined;
  let rsaModulusHex: string | undefined;
  if (certificate.publicKey.asymmetricKeyType === 'rsa') {
    const jwk = certificate.publicKey.export({ format: 'jwk' });
    if (jwk.n) {
      const modulus = base64UrlToBuffer(jwk.n);
      rsaModulusHex = modulus.toString('hex').toUpperCase();
      rsaModulusDecimal = BigInt(`0x${rsaModulusHex}`).toString(10);
    }
  }

  return {
    subject: certificate.subject,
    md5: hash(certificate.raw, 'md5'),
    sha1: normalizeFingerprint(certificate.fingerprint),
    sha256: normalizeFingerprint(certificate.fingerprint256),
    spkiSha256: hash(Buffer.from(spki), 'sha256'),
    publicKeyAlgorithm: algorithm,
    ...(publicKeySize ? { publicKeySize } : {}),
    ...(rsaModulusDecimal ? { rsaModulusDecimal } : {}),
    ...(rsaModulusHex ? { rsaModulusHex } : {}),
  };
}

export async function readPublicCertificate(path: string): Promise<PublicCertificateInfo> {
  const extension = extname(path).toLowerCase();
  if (!['.cer', '.crt', '.der'].includes(extension)) {
    throw new Error('Only public .cer, .crt, or .der certificate files are accepted.');
  }
  const data = await readFile(path);
  return parsePublicCertificate(data);
}
