import { existsSync } from 'node:fs';
import { createResult, toolError } from '../rules/result.js';
import type { AuditResult, Check } from '../types.js';
import { normalizeFingerprint } from '../utils/hash.js';
import { discoverAndroidTools, runTool, type AndroidTools } from '../utils/process.js';
import { parseApkSignerOutput, type ApkSignerInfo } from './apksigner.js';
import { readPublicCertificate, type PublicCertificateInfo } from './certificate.js';

export interface ComparisonOptions {
  tools?: AndroidTools;
}

export function compareCertificateIdentity(
  signer: Pick<ApkSignerInfo, 'md5' | 'sha1' | 'sha256' | 'publicKeySha256'>,
  certificate: Pick<PublicCertificateInfo, 'md5' | 'sha1' | 'sha256' | 'spkiSha256'>
): { outcome: 'MATCH' | 'MISMATCH'; mismatches: string[] } {
  const pairs: Array<[string, string | undefined, string]> = [
    ['Certificate MD5', signer.md5, certificate.md5],
    ['Certificate SHA1', signer.sha1, certificate.sha1],
    ['Certificate SHA256', signer.sha256, certificate.sha256],
    ['Public Key SPKI', signer.publicKeySha256, certificate.spkiSha256],
  ];
  const mismatches = pairs
    .filter(
      ([, apkValue, certValue]) =>
        !apkValue || normalizeFingerprint(apkValue) !== normalizeFingerprint(certValue)
    )
    .map(([name]) => name);
  return { outcome: mismatches.length === 0 ? 'MATCH' : 'MISMATCH', mismatches };
}

export async function compareApkAndCertificate(
  apkPath: string,
  certPath: string,
  options: ComparisonOptions = {}
): Promise<AuditResult> {
  if (!existsSync(apkPath)) return toolError('compare.apk-path', 'APK path does not exist.');
  if (!existsSync(certPath))
    return toolError('compare.cert-path', 'Certificate path does not exist.');

  const tools = options.tools ?? discoverAndroidTools();
  if (!tools.apksigner) {
    return toolError(
      'compare.apksigner',
      'Missing apksigner. Install Android SDK Build Tools separately.'
    );
  }

  const verification = runTool(tools.apksigner, ['verify', '--verbose', '--print-certs', apkPath]);
  if (verification.code !== 0) {
    return createResult([
      {
        id: 'compare.apk-signature',
        status: 'BLOCKED',
        message: 'APK signature validation failed.',
      },
    ]);
  }

  let certificate: PublicCertificateInfo;
  try {
    certificate = await readPublicCertificate(certPath);
  } catch {
    return toolError(
      'compare.certificate',
      'Public certificate could not be parsed. Private key and keystore inputs are not accepted.'
    );
  }

  const signer = parseApkSignerOutput(`${verification.stdout}\n${verification.stderr}`);
  const comparison = compareCertificateIdentity(signer, certificate);
  const check: Check = {
    id: 'compare.certificate-identity',
    status: comparison.outcome === 'MATCH' ? 'PASS' : 'BLOCKED',
    message: comparison.outcome,
    details: {
      outcome: comparison.outcome,
      ...(comparison.mismatches.length > 0
        ? { mismatchedFields: comparison.mismatches.join(', ') }
        : {}),
    },
  };
  return createResult([check]);
}
