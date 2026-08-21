import { existsSync } from 'node:fs';
import { createResult, toolError } from '../rules/result.js';
import type { AuditResult, Check } from '../types.js';
import { discoverAndroidTools, runTool, type AndroidTools } from '../utils/process.js';
import { parsePublicCertificate } from './certificate.js';
import { extractApkMetadata } from './metadata.js';

export const ICP_DISCLAIMER =
  'Experimental helper. Always verify current filing-provider requirements.';

export interface IcpOptions {
  tools?: AndroidTools;
}

export async function inspectIcp(apkPath: string, options: IcpOptions = {}): Promise<AuditResult> {
  if (!existsSync(apkPath)) return toolError('icp.apk-path', 'APK path does not exist.');
  const tools = options.tools ?? discoverAndroidTools();
  if (!tools.keytool) {
    return toolError('icp.keytool', 'Missing keytool. Install a local JDK separately.');
  }

  const metadata = extractApkMetadata(apkPath, tools);
  if (!metadata?.packageName) {
    return toolError(
      'icp.metadata-tool',
      'Package name could not be extracted. Install apkanalyzer, aapt, or aapt2 separately.'
    );
  }

  const certificateOutput = runTool(tools.keytool, ['-printcert', '-jarfile', apkPath, '-rfc']);
  if (certificateOutput.code !== 0) {
    return toolError(
      'icp.certificate',
      'Signer certificate could not be exported by local keytool for this APK.'
    );
  }
  const pem = certificateOutput.stdout.match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/
  )?.[0];
  if (!pem) return toolError('icp.certificate', 'Signer public certificate was not found.');

  try {
    const certificate = parsePublicCertificate(pem);
    const rsa = certificate.publicKeyAlgorithm === 'RSA';
    const check: Check = {
      id: 'icp.rsa-helper',
      status: rsa ? 'PASS' : 'WARN',
      message: rsa
        ? 'RSA signer information extracted for experimental filing assistance.'
        : 'Signer is not RSA; RSA modulus output is unavailable.',
      details: {
        packageName: metadata.packageName,
        certificateMd5: certificate.md5,
        publicKeyAlgorithm: certificate.publicKeyAlgorithm,
        ...(certificate.rsaModulusDecimal
          ? { rsaModulusDecimal: certificate.rsaModulusDecimal }
          : {}),
        ...(certificate.rsaModulusHex ? { rsaModulusHex: certificate.rsaModulusHex } : {}),
        disclaimer: ICP_DISCLAIMER,
      },
    };
    return createResult([check]);
  } catch {
    return toolError('icp.certificate', 'Signer public certificate could not be parsed.');
  }
}
