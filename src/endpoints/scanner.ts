import { readFile, stat } from 'node:fs/promises';
import { relative } from 'node:path';
import { createResult, toolError } from '../rules/result.js';
import type { AuditResult, Check, Status } from '../types.js';
import { collectTextFiles } from '../utils/files.js';

export interface EndpointFinding {
  filename: string;
  line: number;
  rule: string;
  context: string;
  severity: Extract<Status, 'WARN' | 'BLOCKED'>;
}

interface Candidate {
  value: string;
  index: number;
  rule: string;
  severity: Extract<Status, 'WARN' | 'BLOCKED'>;
}

const safeHttpPrefixes = [
  'http://schemas.android.com/',
  'http://www.w3.org/',
  'http://www.apache.org/',
  'http://xml.org/',
];

function isAllowed(value: string, filename: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => {
    try {
      const expression = new RegExp(pattern, 'i');
      return expression.test(value) || expression.test(filename);
    } catch {
      const normalized = pattern.toLowerCase();
      return (
        value.toLowerCase().includes(normalized) || filename.toLowerCase().includes(normalized)
      );
    }
  });
}

function classifyUrl(url: string, index: number): Candidate[] {
  const normalized = url.toLowerCase();
  const findings: Candidate[] = [];
  let hostname = '';
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return findings;
  }

  if (['localhost', '127.0.0.1', '0.0.0.0', '::1'].includes(hostname)) {
    findings.push({ value: url, index, rule: 'local-endpoint-url', severity: 'BLOCKED' });
  }
  if (hostname.includes('ngrok') || hostname.endsWith('.trycloudflare.com')) {
    findings.push({ value: url, index, rule: 'temporary-tunnel-endpoint', severity: 'BLOCKED' });
  }
  if (hostname.endsWith('.test') || hostname.endsWith('.local')) {
    findings.push({ value: url, index, rule: 'non-production-domain', severity: 'WARN' });
  }
  if (/(^|[.-])(uat|research)([.-]|$)/i.test(hostname)) {
    findings.push({ value: url, index, rule: 'non-production-environment', severity: 'WARN' });
  }
  if (
    normalized.startsWith('http://') &&
    !safeHttpPrefixes.some((prefix) => normalized.startsWith(prefix))
  ) {
    findings.push({ value: url, index, rule: 'cleartext-http-endpoint', severity: 'BLOCKED' });
  }
  return findings;
}

function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

function safeContext(content: string, index: number): string {
  const lineStart = content.lastIndexOf('\n', index) + 1;
  const lineEndCandidate = content.indexOf('\n', index);
  const lineEnd = lineEndCandidate === -1 ? content.length : lineEndCandidate;
  return content
    .slice(lineStart, lineEnd)
    .trim()
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[redacted]@')
    .replace(/([?&](?:token|key|secret|password)=)[^&\s]+/gi, '$1[redacted]')
    .slice(0, 180);
}

export function scanEndpointContent(
  content: string,
  filename: string,
  allowPatterns: readonly string[] = []
): EndpointFinding[] {
  const candidates: Candidate[] = [];
  const urlPattern = /https?:\/\/[^\s'"`<>\\)\]]+/gi;
  for (const match of content.matchAll(urlPattern)) {
    if (match.index === undefined) continue;
    candidates.push(...classifyUrl(match[0], match.index));
  }

  const hostAssignment =
    /\b(?:host|hostname|baseUrl|apiUrl|server)\s*[:=]\s*['"]?(localhost|127\.0\.0\.1|0\.0\.0\.0)(?=['"\s,;}])/gi;
  for (const match of content.matchAll(hostAssignment)) {
    if (match.index === undefined) continue;
    candidates.push({
      value: match[0],
      index: match.index,
      rule: 'local-host-configuration',
      severity: 'BLOCKED',
    });
  }

  const tunnelPhrase = /\bcloudflare\s+tunnel\b/gi;
  for (const match of content.matchAll(tunnelPhrase)) {
    if (match.index === undefined) continue;
    candidates.push({
      value: match[0],
      index: match.index,
      rule: 'temporary-tunnel-reference',
      severity: 'WARN',
    });
  }

  const seen = new Set<string>();
  const findings: EndpointFinding[] = [];
  for (const candidate of candidates) {
    if (isAllowed(candidate.value, filename, allowPatterns)) continue;
    const line = lineNumberAt(content, candidate.index);
    const key = `${candidate.rule}:${line}:${candidate.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      filename,
      line,
      rule: candidate.rule,
      context: safeContext(content, candidate.index),
      severity: candidate.severity,
    });
  }
  return findings;
}

export async function scanEndpoints(
  targetPath: string,
  allowPatterns: readonly string[] = []
): Promise<AuditResult> {
  try {
    await stat(targetPath);
  } catch {
    return toolError('endpoints.path', 'Endpoint scan path does not exist or cannot be read.');
  }

  let files: string[];
  try {
    files = await collectTextFiles(targetPath);
  } catch {
    return toolError('endpoints.read', 'Endpoint scan path could not be inspected safely.');
  }

  const checks: Check[] = [];
  for (const file of files) {
    let content: string;
    try {
      content = await readFile(file, 'utf8');
    } catch {
      checks.push({
        id: 'endpoints.file-read',
        status: 'TOOL_ERROR',
        message: 'A candidate text file could not be read.',
        location: relative(targetPath, file) || file.split(/[\\/]/).pop() || 'input',
      });
      continue;
    }
    const displayName = relative(targetPath, file) || file.split(/[\\/]/).pop() || 'input';
    for (const finding of scanEndpointContent(content, displayName, allowPatterns)) {
      checks.push({
        id: `endpoints.${finding.rule}`,
        status: finding.severity,
        message: 'Potential non-production endpoint detected.',
        location: `${finding.filename}:${finding.line}`,
        details: {
          filename: finding.filename,
          rule: finding.rule,
          context: finding.context,
          severity: finding.severity,
        },
      });
    }
  }

  if (checks.length === 0) {
    checks.push({
      id: 'endpoints.clean',
      status: 'PASS',
      message: 'No disallowed endpoint patterns were detected.',
      details: { filesScanned: files.length },
    });
  }
  return createResult(checks);
}
