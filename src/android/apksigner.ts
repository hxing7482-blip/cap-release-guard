import { normalizeFingerprint } from '../utils/hash.js';

export interface ApkSignerInfo {
  signerCount: number;
  subject?: string;
  md5?: string;
  sha1?: string;
  sha256?: string;
  publicKeyAlgorithm?: string;
  publicKeySize?: number;
  publicKeySha256?: string;
  schemes: {
    v1?: boolean;
    v2?: boolean;
    v3?: boolean;
    v4?: boolean;
  };
}

function capture(output: string, expression: RegExp): string | undefined {
  return output.match(expression)?.[1]?.trim();
}

function digest(output: string, label: string): string | undefined {
  const value = capture(
    output,
    new RegExp(`Signer #\\d+ certificate ${label} digest:\\s*([^\\r\\n]+)`, 'i')
  );
  return value ? normalizeFingerprint(value) : undefined;
}

export function parseApkSignerOutput(output: string): ApkSignerInfo {
  const signerNumbers = [...output.matchAll(/Signer #(\d+)/gi)].map((match) => Number(match[1]));
  const signerCount = signerNumbers.length > 0 ? Math.max(...signerNumbers) : 0;
  const publicKeySizeText = capture(
    output,
    /Signer #\d+ certificate public key size \(bits\):\s*(\d+)/i
  );
  const schemeValue = (version: number): boolean | undefined => {
    const value = capture(
      output,
      new RegExp(`Verified using v${version} scheme[^:]*:\\s*(true|false)`, 'i')
    );
    return value === undefined ? undefined : value.toLowerCase() === 'true';
  };
  const publicKeyDigest = capture(
    output,
    /Signer #\d+ certificate public key SHA-256 digest:\s*([^\r\n]+)/i
  );
  const v1 = schemeValue(1);
  const v2 = schemeValue(2);
  const v3 = schemeValue(3);
  const v4 = schemeValue(4);

  const subject = capture(output, /Signer #\d+ certificate DN:\s*([^\r\n]+)/i);
  const md5 = digest(output, 'MD5');
  const sha1 = digest(output, 'SHA-1');
  const sha256 = digest(output, 'SHA-256');
  const publicKeyAlgorithm = capture(
    output,
    /Signer #\d+ certificate public key algorithm:\s*([^\r\n]+)/i
  );
  const publicKeySize = publicKeySizeText ? Number(publicKeySizeText) : undefined;

  return {
    signerCount,
    ...(subject ? { subject } : {}),
    ...(md5 ? { md5 } : {}),
    ...(sha1 ? { sha1 } : {}),
    ...(sha256 ? { sha256 } : {}),
    ...(publicKeyAlgorithm ? { publicKeyAlgorithm } : {}),
    ...(publicKeySize ? { publicKeySize } : {}),
    ...(publicKeyDigest ? { publicKeySha256: normalizeFingerprint(publicKeyDigest) } : {}),
    schemes: {
      ...(v1 !== undefined ? { v1 } : {}),
      ...(v2 !== undefined ? { v2 } : {}),
      ...(v3 !== undefined ? { v3 } : {}),
      ...(v4 !== undefined ? { v4 } : {}),
    },
  };
}

export function isAndroidDebugSigner(subject: string | undefined): boolean {
  return subject !== undefined && /Android\s+Debug/i.test(subject);
}
