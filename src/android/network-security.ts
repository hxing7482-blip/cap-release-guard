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

interface XmlElement {
  name: string;
  attributes: Map<string, string>;
  children: XmlElement[];
  directText: string[];
  index: number;
}

interface StartTag {
  name: string;
  attributes: Map<string, string>;
  selfClosing: boolean;
}

const manifestRelativePaths = {
  main: 'android/app/src/main/AndroidManifest.xml',
  release: 'android/app/src/release/AndroidManifest.xml',
} as const;

const predefinedEntities = new Map([
  ['amp', '&'],
  ['apos', "'"],
  ['gt', '>'],
  ['lt', '<'],
  ['quot', '"'],
]);

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

function isXmlNameStart(character: string | undefined): boolean {
  return character !== undefined && /[A-Za-z_:]/.test(character);
}

function isXmlNameCharacter(character: string | undefined): boolean {
  return character !== undefined && /[A-Za-z0-9_.:-]/.test(character);
}

function readXmlName(value: string, start: number): { name: string; end: number } {
  if (!isXmlNameStart(value[start])) throw new Error('Invalid XML name.');
  let end = start + 1;
  while (isXmlNameCharacter(value[end])) end += 1;
  return { name: value.slice(start, end), end };
}

function skipWhitespace(value: string, start: number): number {
  let cursor = start;
  while (/\s/.test(value[cursor] ?? '')) cursor += 1;
  return cursor;
}

function decodePredefinedEntities(value: string): string {
  let decoded = '';
  let cursor = 0;
  while (cursor < value.length) {
    const ampersand = value.indexOf('&', cursor);
    if (ampersand === -1) return decoded + value.slice(cursor);
    decoded += value.slice(cursor, ampersand);
    const semicolon = value.indexOf(';', ampersand + 1);
    if (semicolon === -1) throw new Error('Unterminated XML entity reference.');
    const entityName = value.slice(ampersand + 1, semicolon);
    const replacement = predefinedEntities.get(entityName);
    if (replacement === undefined) throw new Error('Unsupported XML entity reference.');
    decoded += replacement;
    cursor = semicolon + 1;
  }
  return decoded;
}

function parseStartTag(value: string): StartTag {
  let body = value.trim();
  const selfClosing = body.endsWith('/');
  if (selfClosing) body = body.slice(0, -1).trimEnd();

  let cursor = skipWhitespace(body, 0);
  const elementName = readXmlName(body, cursor);
  cursor = elementName.end;
  const attributes = new Map<string, string>();

  while (cursor < body.length) {
    const next = skipWhitespace(body, cursor);
    if (next === cursor) throw new Error('XML attributes must be separated by whitespace.');
    cursor = next;
    if (cursor >= body.length) break;

    const attributeName = readXmlName(body, cursor);
    cursor = skipWhitespace(body, attributeName.end);
    if (body[cursor] !== '=') throw new Error('XML attribute is missing an equals sign.');
    cursor = skipWhitespace(body, cursor + 1);
    const quote = body[cursor];
    if (quote !== '"' && quote !== "'") throw new Error('XML attributes must be quoted.');
    const endQuote = body.indexOf(quote, cursor + 1);
    if (endQuote === -1) throw new Error('XML attribute quote is not closed.');
    if (attributes.has(attributeName.name)) throw new Error('Duplicate XML attribute.');
    attributes.set(attributeName.name, decodePredefinedEntities(body.slice(cursor + 1, endQuote)));
    cursor = endQuote + 1;
  }

  return { name: elementName.name, attributes, selfClosing };
}

function findTagEnd(content: string, start: number): number {
  let quote: '"' | "'" | undefined;
  for (let cursor = start; cursor < content.length; cursor += 1) {
    const character = content[cursor];
    if (quote) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '>') return cursor;
  }
  throw new Error('XML tag is not closed.');
}

function rejectExecutableElement(name: string): void {
  const normalized = name.toLowerCase();
  if (normalized === 'include' || normalized.endsWith(':include') || normalized.startsWith('xi:')) {
    throw new Error('XInclude is not supported.');
  }
}

function parseXml(content: string): XmlElement {
  const stack: XmlElement[] = [];
  let root: XmlElement | undefined;
  let cursor = 0;
  let hasXmlDeclaration = false;

  while (cursor < content.length) {
    if (content[cursor] !== '<') {
      const nextTag = content.indexOf('<', cursor);
      const end = nextTag === -1 ? content.length : nextTag;
      const text = decodePredefinedEntities(content.slice(cursor, end));
      const current = stack.at(-1);
      if (current) current.directText.push(text);
      else if (text.trim().length > 0) throw new Error('Text is not allowed outside the root.');
      cursor = end;
      continue;
    }

    if (content.startsWith('<!--', cursor)) {
      const commentEnd = content.indexOf('-->', cursor + 4);
      if (commentEnd === -1) throw new Error('XML comment is not closed.');
      cursor = commentEnd + 3;
      continue;
    }

    if (content.startsWith('<?', cursor)) {
      const instructionEnd = content.indexOf('?>', cursor + 2);
      if (instructionEnd === -1) throw new Error('XML processing instruction is not closed.');
      const instruction = content.slice(cursor + 2, instructionEnd).trim();
      if (
        hasXmlDeclaration ||
        root !== undefined ||
        !/^xml(?:\s|$)/i.test(instruction) ||
        /^xml-/i.test(instruction)
      ) {
        throw new Error('XML processing instructions are not supported.');
      }
      hasXmlDeclaration = true;
      cursor = instructionEnd + 2;
      continue;
    }

    if (content.startsWith('<!', cursor)) {
      throw new Error('DTD, ENTITY, CDATA, and other declarations are not supported.');
    }

    const tagEnd = findTagEnd(content, cursor + 1);
    const tagBody = content.slice(cursor + 1, tagEnd);
    const trimmedTagBody = tagBody.trim();
    if (trimmedTagBody.startsWith('/')) {
      const closing = trimmedTagBody.slice(1).trim();
      const closingName = readXmlName(closing, 0);
      if (skipWhitespace(closing, closingName.end) !== closing.length) {
        throw new Error('Invalid closing XML tag.');
      }
      const current = stack.pop();
      if (!current || current.name !== closingName.name) {
        throw new Error('Mismatched closing XML tag.');
      }
    } else {
      const tag = parseStartTag(tagBody);
      rejectExecutableElement(tag.name);
      const element: XmlElement = {
        name: tag.name,
        attributes: tag.attributes,
        children: [],
        directText: [],
        index: cursor,
      };
      const parent = stack.at(-1);
      if (parent) parent.children.push(element);
      else {
        if (root) throw new Error('Multiple XML root elements are not supported.');
        root = element;
      }
      if (!tag.selfClosing) stack.push(element);
    }
    cursor = tagEnd + 1;
  }

  if (stack.length > 0 || !root) throw new Error('XML document is incomplete.');
  return root;
}

function booleanAttribute(element: XmlElement, name: string): boolean | undefined {
  const value = element.attributes.get(name);
  if (value === undefined) return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  throw new Error('Invalid boolean XML attribute.');
}

function directChildren(element: XmlElement, name: string): XmlElement[] {
  return element.children.filter((child) => child.name === name);
}

function safeDomain(value: string): string | undefined {
  const domain = value.trim().toLowerCase();
  return /^[a-z0-9.-]+$/.test(domain) ? domain : undefined;
}

function analyzeDomainConfig(
  element: XmlElement,
  inheritedCleartext: boolean | undefined,
  document: XmlDocument,
  location: string,
  checks: Check[]
): void {
  const effectiveCleartext =
    booleanAttribute(element, 'cleartextTrafficPermitted') ?? inheritedCleartext;
  const seenDomains = new Set<string>();

  for (const domainElement of directChildren(element, 'domain')) {
    if (domainElement.children.length > 0) throw new Error('Nested domain content is unsupported.');
    const domain = safeDomain(domainElement.directText.join(''));
    if (!domain) throw new Error('Invalid domain value.');
    const includeSubdomains = booleanAttribute(domainElement, 'includeSubdomains') ?? false;
    const domainKey = `${domain}\u0000${String(includeSubdomains)}`;
    if (seenDomains.has(domainKey)) continue;
    seenDomains.add(domainKey);

    if (effectiveCleartext === true) {
      checks.push({
        id: RULE_IDS.androidNetworkSecurityCleartext,
        status: 'BLOCKED',
        message: 'A release network security domain-config permits cleartext traffic.',
        location: `${location}:${lineAt(document.content, domainElement.index)}`,
        details: { domain, includeSubdomains },
      });
    }
  }

  for (const child of directChildren(element, 'domain-config')) {
    analyzeDomainConfig(child, effectiveCleartext, document, location, checks);
  }
}

function inspectNetworkConfig(root: string, document: XmlDocument): Check[] {
  const location = safeRelative(root, document.path);
  try {
    const config = parseXml(document.content);
    if (config.name !== 'network-security-config') {
      throw new Error('Unexpected network security XML root.');
    }

    const checks: Check[] = [];
    const baseConfigs = directChildren(config, 'base-config');
    if (baseConfigs.length > 1) throw new Error('Multiple base-config elements are unsupported.');
    const baseConfig = baseConfigs[0];
    const baseCleartext = baseConfig
      ? booleanAttribute(baseConfig, 'cleartextTrafficPermitted')
      : undefined;

    if (baseConfig && baseCleartext === true) {
      checks.push({
        id: RULE_IDS.androidNetworkSecurityCleartext,
        status: 'BLOCKED',
        message: 'Release network security base-config permits cleartext traffic.',
        location: `${location}:${lineAt(document.content, baseConfig.index)}`,
      });
    }

    for (const domainConfig of directChildren(config, 'domain-config')) {
      analyzeDomainConfig(domainConfig, baseCleartext, document, location, checks);
    }

    if (checks.length === 0) {
      checks.push({
        id: RULE_IDS.androidNetworkSecurityCleartext,
        status: 'PASS',
        message: 'Release network security configuration does not explicitly permit cleartext.',
        location,
      });
    }

    if (directChildren(config, 'debug-overrides').length > 0) {
      checks.push({
        id: 'android.network-security.debug-overrides',
        status: 'PASS',
        message: 'Debug-only network security overrides were not treated as a release failure.',
        location,
      });
    }
    return checks;
  } catch {
    return [
      {
        id: 'android.network-security.xml',
        status: 'TOOL_ERROR',
        message: 'The release network security XML could not be safely analyzed.',
        location,
      },
    ];
  }
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
