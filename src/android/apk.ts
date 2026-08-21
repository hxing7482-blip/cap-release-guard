import { existsSync } from 'node:fs';
import { RULE_IDS } from '../rules/ids.js';
import { createResult, toolError } from '../rules/result.js';
import type { AuditResult, Check, SafeDetailValue } from '../types.js';
import { discoverAndroidTools, runTool, type AndroidTools } from '../utils/process.js';
import { isAndroidDebugSigner, parseApkSignerOutput } from './apksigner.js';
import { extractApkMetadata } from './metadata.js';

export interface ApkAnalysisOptions {
  tools?: AndroidTools;
}

function metadataDetails(
  metadata: ReturnType<typeof extractApkMetadata>
): Record<string, SafeDetailValue> {
  if (!metadata) return {};
  return {
    ...(metadata.packageName ? { packageName: metadata.packageName } : {}),
    ...(metadata.versionName ? { versionName: metadata.versionName } : {}),
    ...(metadata.versionCode ? { versionCode: metadata.versionCode } : {}),
    ...(metadata.minSdk ? { minSdk: metadata.minSdk } : {}),
    ...(metadata.targetSdk ? { targetSdk: metadata.targetSdk } : {}),
    ...(metadata.debuggable !== undefined ? { debuggable: metadata.debuggable } : {}),
  };
}

export async function analyzeApk(
  apkPath: string,
  options: ApkAnalysisOptions = {}
): Promise<AuditResult> {
  if (!existsSync(apkPath)) {
    return toolError('apk.path', 'APK path does not exist.');
  }
  if (!apkPath.toLowerCase().endsWith('.apk')) {
    return toolError('apk.path', 'Input must be an APK file.');
  }

  const tools = options.tools ?? discoverAndroidTools();
  const checks: Check[] = [];
  const metadata = extractApkMetadata(apkPath, tools);
  if (!metadata) {
    checks.push({
      id: 'apk.metadata-tools',
      status: 'TOOL_ERROR',
      message:
        'Missing or unusable apkanalyzer, aapt, or aapt2. Install Android SDK tools separately.',
    });
  } else {
    checks.push({
      id: 'apk.metadata',
      status: metadata.packageName ? 'PASS' : 'WARN',
      message: metadata.packageName
        ? 'APK manifest metadata extracted.'
        : 'APK metadata was only partially extracted.',
      details: metadataDetails(metadata),
    });
    checks.push({
      id: RULE_IDS.androidDebuggable,
      status:
        metadata.debuggable === true ? 'BLOCKED' : metadata.debuggable === false ? 'PASS' : 'WARN',
      message:
        metadata.debuggable === true
          ? 'APK manifest sets android:debuggable=true.'
          : metadata.debuggable === false
            ? 'APK is not debuggable.'
            : 'APK debuggable state could not be determined.',
    });
  }

  if (!tools.apksigner) {
    checks.push({
      id: 'apk.signature-tool',
      status: 'TOOL_ERROR',
      message: 'Missing apksigner. Install Android SDK Build Tools separately.',
    });
    return createResult(checks);
  }

  const verification = runTool(tools.apksigner, ['verify', '--verbose', '--print-certs', apkPath]);
  if (verification.code !== 0) {
    checks.push({
      id: 'apk.signature-valid',
      status: 'BLOCKED',
      message: 'APK signature validation failed.',
    });
    return createResult(checks);
  }

  const signer = parseApkSignerOutput(`${verification.stdout}\n${verification.stderr}`);
  checks.push({
    id: 'apk.signature-valid',
    status: 'PASS',
    message: 'APK signature is valid.',
    details: {
      signerCount: signer.signerCount,
      ...(signer.subject ? { signerSubject: signer.subject } : {}),
      ...(signer.md5 ? { certificateMd5: signer.md5 } : {}),
      ...(signer.sha1 ? { certificateSha1: signer.sha1 } : {}),
      ...(signer.sha256 ? { certificateSha256: signer.sha256 } : {}),
      ...(signer.publicKeyAlgorithm ? { publicKeyAlgorithm: signer.publicKeyAlgorithm } : {}),
      ...(signer.publicKeySize ? { publicKeySize: signer.publicKeySize } : {}),
    },
  });
  checks.push({
    id: RULE_IDS.androidDebugSigner,
    status: isAndroidDebugSigner(signer.subject) ? 'BLOCKED' : 'PASS',
    message: isAndroidDebugSigner(signer.subject)
      ? 'Android Debug signer certificate detected.'
      : 'Android Debug signer certificate not detected.',
  });
  checks.push({
    id: 'apk.signature-schemes',
    status: Object.values(signer.schemes).some(Boolean) ? 'PASS' : 'WARN',
    message: 'APK signature scheme support inspected.',
    details: {
      v1: signer.schemes.v1 ?? false,
      v2: signer.schemes.v2 ?? false,
      v3: signer.schemes.v3 ?? false,
      v4: signer.schemes.v4 ?? false,
    },
  });

  return createResult(checks);
}
