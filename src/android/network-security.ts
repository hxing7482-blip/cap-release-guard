import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { RULE_IDS } from '../rules/ids.js';
import type { Check } from '../types.js';

interface XmlDocument {
  content: string;
  path: string;
}

interface AttributeValue {
  value: string;
  index: number;
}

const manifestRelativePaths = {
  main: 'android/app/src/main/AndroidManifest.xml',
  release: 'android/app/src/release/AndroidManifest.xml',
} as const;

function lineAt(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

function safeRelative(root: string, path: string): string {
  return relative(root, path).replaceAll('\\', '/');
}

async function readOptional(path: string): Promise<XmlDocument | undefined> {
  if (!existsSync(path)) return undefined;
  return { content: await readFile(path, 'utf8'), path };
}

function applicationAttribute(document: XmlDocument, name: string): AttributeValue | undefined {
  const application = /<application\b[^>]*>/i.exec(document.content);
  if (!application || application.index === undefined) return undefined;
  const attribute = new RegExp(`\\bandroid:${name}\\s*=\\s*["']([^"']+)["']`, 'i').exec(
    application[0]
  );
  if (!attribute || attribute.index === undefined || !attribute[1]) return undefined;
  return { value: attribute[1].trim(), index: application.index + attribute.index };
}

function maskXmlSection(value: string): string {
  return value.replace(/[^\r\n]/g, ' ');
}

function analyzableXml(content: string): { content: string; hasDebugOverrides: boolean } {
  const withoutComments = content.replace(/<!--[\s\S]*?-->/g, maskXmlSection);
  const debugExpression = /<debug-overrides\b[^>]*(?:\/>|>[\s\S]*?<\/debug-overrides\s*>)/gi;
  const hasDebugOverrides = debugExpression.test(withoutComments);
  debugExpression.lastIndex = 0;
  return {
    content: withoutComments.replace(debugExpression, maskXmlSection),
    hasDebugOverrides,
  };
}

function cleartextAttribute(tag: string): boolean {
  return /\bcleartextTrafficPermitted\s*=\s*["']true["']/i.test(tag);
}

function safeDomain(value: string): string | undefined {
  const domain = value.trim().toLowerCase();
  return /^[a-z0-9.-]+$/.test(domain) ? domain : undefined;
}

function inspectNetworkConfig(root: string, document: XmlDocument): Check[] {
  const checks: Check[] = [];
  const analysis = analyzableXml(document.content);
  const location = safeRelative(root, document.path);

  for (const match of analysis.content.matchAll(/<base-config\b[^>]*>/gi)) {
    if (match.index === undefined || !cleartextAttribute(match[0])) continue;
    checks.push({
      id: RULE_IDS.androidNetworkSecurityCleartext,
      status: 'BLOCKED',
      message: 'Release network security base-config permits cleartext traffic.',
      location: `${location}:${lineAt(document.content, match.index)}`,
    });
  }

  for (const match of analysis.content.matchAll(
    /<domain-config\b[^>]*>[\s\S]*?<\/domain-config\s*>/gi
  )) {
    if (match.index === undefined) continue;
    const startTag = /^<domain-config\b[^>]*>/i.exec(match[0])?.[0];
    if (!startTag || !cleartextAttribute(startTag)) continue;
    const domains = [...match[0].matchAll(/<domain\b[^>]*>([^<]+)<\/domain\s*>/gi)]
      .map((domainMatch) => safeDomain(domainMatch[1] ?? ''))
      .filter((domain): domain is string => domain !== undefined);
    const uniqueDomains = [...new Set(domains)].sort();
    if (uniqueDomains.length === 0) {
      checks.push({
        id: RULE_IDS.androidNetworkSecurityCleartext,
        status: 'BLOCKED',
        message: 'A release network security domain-config permits cleartext traffic.',
        location: `${location}:${lineAt(document.content, match.index)}`,
      });
      continue;
    }
    for (const domain of uniqueDomains) {
      checks.push({
        id: RULE_IDS.androidNetworkSecurityCleartext,
        status: 'BLOCKED',
        message: 'A release network security domain-config permits cleartext traffic.',
        location: `${location}:${lineAt(document.content, match.index)}`,
        details: { domain },
      });
    }
  }

  if (checks.length === 0) {
    checks.push({
      id: RULE_IDS.androidNetworkSecurityCleartext,
      status: 'PASS',
      message: 'Release network security configuration does not explicitly permit cleartext.',
      location,
    });
  }
  if (analysis.hasDebugOverrides) {
    checks.push({
      id: 'android.network-security.debug-overrides',
      status: 'PASS',
      message: 'Debug-only network security overrides were not treated as a release failure.',
      location,
    });
  }
  return checks;
}

export async function inspectAndroidNetworkSecurity(root: string): Promise<Check[]> {
  const mainPath = join(root, ...manifestRelativePaths.main.split('/'));
  const releasePath = join(root, ...manifestRelativePaths.release.split('/'));

  let mainManifest: XmlDocument | undefined;
  let releaseManifest: XmlDocument | undefined;
  try {
    [mainManifest, releaseManifest] = await Promise.all([
      readOptional(mainPath),
      readOptional(releasePath),
    ]);
  } catch {
    return [
      {
        id: 'android.manifest-read',
        status: 'TOOL_ERROR',
        message: 'Android release manifest inputs could not be read.',
      },
    ];
  }

  if (!mainManifest && !releaseManifest) {
    return [
      {
        id: 'android.manifest',
        status: 'WARN',
        message: 'Main or release AndroidManifest.xml was not detected.',
      },
    ];
  }

  const mainCleartext = mainManifest
    ? applicationAttribute(mainManifest, 'usesCleartextTraffic')
    : undefined;
  const releaseCleartext = releaseManifest
    ? applicationAttribute(releaseManifest, 'usesCleartextTraffic')
    : undefined;
  const effectiveCleartext = releaseCleartext ?? mainCleartext;
  const cleartextManifest = releaseCleartext ? releaseManifest : mainManifest;
  const checks: Check[] = [];

  if (effectiveCleartext?.value.toLowerCase() === 'true' && cleartextManifest) {
    checks.push({
      id: RULE_IDS.androidCleartextTraffic,
      status: 'BLOCKED',
      message: 'The effective release manifest permits cleartext traffic.',
      location: `${safeRelative(root, cleartextManifest.path)}:${lineAt(
        cleartextManifest.content,
        effectiveCleartext.index
      )}`,
    });
  } else {
    checks.push({
      id: RULE_IDS.androidCleartextTraffic,
      status: 'PASS',
      message:
        effectiveCleartext?.value.toLowerCase() === 'false'
          ? 'The effective release manifest disables cleartext traffic.'
          : 'The effective release manifest does not explicitly enable cleartext traffic.',
      ...(cleartextManifest ? { location: safeRelative(root, cleartextManifest.path) } : {}),
    });
  }

  const mainConfig = mainManifest
    ? applicationAttribute(mainManifest, 'networkSecurityConfig')
    : undefined;
  const releaseConfig = releaseManifest
    ? applicationAttribute(releaseManifest, 'networkSecurityConfig')
    : undefined;
  const effectiveConfig = releaseConfig ?? mainConfig;
  if (!effectiveConfig) {
    checks.push({
      id: 'android.network-security.config',
      status: 'PASS',
      message: 'No release networkSecurityConfig reference was detected.',
    });
    return checks;
  }

  const resourceMatch = effectiveConfig.value.match(/^@xml\/([a-zA-Z0-9_]+)$/);
  if (!resourceMatch?.[1]) {
    checks.push({
      id: 'android.network-security.config',
      status: 'WARN',
      message: 'The release networkSecurityConfig reference is not a static @xml resource.',
    });
    return checks;
  }

  const filename = `${resourceMatch[1]}.xml`;
  const releaseResource = join(root, 'android', 'app', 'src', 'release', 'res', 'xml', filename);
  const mainResource = join(root, 'android', 'app', 'src', 'main', 'res', 'xml', filename);
  let document: XmlDocument | undefined;
  try {
    document = (await readOptional(releaseResource)) ?? (await readOptional(mainResource));
  } catch {
    checks.push({
      id: 'android.network-security.read',
      status: 'TOOL_ERROR',
      message: 'The release network security XML could not be read.',
    });
    return checks;
  }

  if (!document) {
    checks.push({
      id: 'android.network-security.missing',
      status: 'TOOL_ERROR',
      message: 'The referenced release network security XML was not found.',
    });
    return checks;
  }

  checks.push(...inspectNetworkConfig(root, document));
  return checks;
}
