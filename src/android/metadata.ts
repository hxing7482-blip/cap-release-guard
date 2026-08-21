import { runTool, type AndroidTools } from '../utils/process.js';

export interface ApkMetadata {
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdk?: string;
  targetSdk?: string;
  debuggable?: boolean;
}

function clean(value: string): string | undefined {
  const normalized = value.trim().replace(/^['"]|['"]$/g, '');
  return normalized || undefined;
}

function analyzeField(tool: string, apkPath: string, field: string): string | undefined {
  const result = runTool(tool, ['manifest', field, apkPath]);
  return result.code === 0 ? clean(result.stdout) : undefined;
}

function parseAaptBadging(output: string): ApkMetadata {
  const packageLine = output.match(/^package:\s+(.+)$/m)?.[1] ?? '';
  const packageName = packageLine.match(/\bname='([^']+)'/)?.[1];
  const versionCode = packageLine.match(/\bversionCode='([^']+)'/)?.[1];
  const versionName = packageLine.match(/\bversionName='([^']+)'/)?.[1];
  const minSdk = output.match(/^sdkVersion:'([^']+)'/m)?.[1];
  const targetSdk = output.match(/^targetSdkVersion:'([^']+)'/m)?.[1];
  const debuggable = /^application-debuggable/m.test(output) ? true : undefined;
  return {
    ...(packageName ? { packageName } : {}),
    ...(versionName ? { versionName } : {}),
    ...(versionCode ? { versionCode } : {}),
    ...(minSdk ? { minSdk } : {}),
    ...(targetSdk ? { targetSdk } : {}),
    ...(debuggable !== undefined ? { debuggable } : {}),
  };
}

export function extractApkMetadata(apkPath: string, tools: AndroidTools): ApkMetadata | undefined {
  if (tools.apkanalyzer) {
    const debuggableValue = analyzeField(tools.apkanalyzer, apkPath, 'debuggable');
    const packageName = analyzeField(tools.apkanalyzer, apkPath, 'application-id');
    const versionName = analyzeField(tools.apkanalyzer, apkPath, 'version-name');
    const versionCode = analyzeField(tools.apkanalyzer, apkPath, 'version-code');
    const minSdk = analyzeField(tools.apkanalyzer, apkPath, 'min-sdk');
    const targetSdk = analyzeField(tools.apkanalyzer, apkPath, 'target-sdk');
    return {
      ...(packageName ? { packageName } : {}),
      ...(versionName ? { versionName } : {}),
      ...(versionCode ? { versionCode } : {}),
      ...(minSdk ? { minSdk } : {}),
      ...(targetSdk ? { targetSdk } : {}),
      ...(debuggableValue ? { debuggable: debuggableValue.toLowerCase() === 'true' } : {}),
    };
  }

  const aapt = tools.aapt ?? tools.aapt2;
  if (!aapt) return undefined;
  const result = runTool(aapt, ['dump', 'badging', apkPath]);
  return result.code === 0 ? parseAaptBadging(result.stdout) : undefined;
}
