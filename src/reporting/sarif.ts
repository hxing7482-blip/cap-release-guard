import { posix, win32 } from 'node:path';
import type { AuditResult, Check } from '../types.js';
import { VERSION } from '../version.js';

type SarifLevel = 'warning' | 'error';

interface ParsedLocation {
  uri: string;
  line?: number;
}

function levelFor(check: Check): SarifLevel {
  return check.status === 'WARN' ? 'warning' : 'error';
}

function safeArtifactUri(value: string): string {
  const normalized = value.replaceAll('\\', '/');
  if (win32.isAbsolute(value) || /^[a-zA-Z]:[\\/]/.test(value)) {
    return encodeURI(win32.basename(value));
  }
  if (posix.isAbsolute(normalized)) {
    return encodeURI(posix.basename(normalized));
  }

  const parts = normalized
    .split('/')
    .filter((part) => part.length > 0 && part !== '.' && part !== '..');
  return encodeURI(parts.join('/') || 'input');
}

function parseLocation(location: string): ParsedLocation {
  const match = location.match(/^(.*):(\d+)$/);
  const path = match?.[1] ?? location;
  const lineText = match?.[2];
  return {
    uri: safeArtifactUri(path),
    ...(lineText ? { line: Number(lineText) } : {}),
  };
}

function findingChecks(result: AuditResult): Check[] {
  return result.checks
    .filter((check) => check.status !== 'PASS')
    .sort((left, right) => {
      return (
        left.id.localeCompare(right.id) ||
        (left.location ?? '').localeCompare(right.location ?? '') ||
        left.message.localeCompare(right.message) ||
        left.status.localeCompare(right.status)
      );
    });
}

export function renderSarif(result: AuditResult): string {
  const findings = findingChecks(result);
  const ruleIds = [...new Set(findings.map((check) => check.id))].sort();
  const ruleIndexes = new Map(ruleIds.map((id, index) => [id, index]));

  const rules = ruleIds.map((id) => {
    const first = findings.find((check) => check.id === id);
    return {
      id,
      name: id,
      shortDescription: { text: first?.message ?? id },
      defaultConfiguration: { level: first ? levelFor(first) : 'warning' },
    };
  });

  const results = findings.map((check) => {
    const location = check.location ? parseLocation(check.location) : undefined;
    return {
      ruleId: check.id,
      ruleIndex: ruleIndexes.get(check.id) ?? 0,
      level: levelFor(check),
      message: { text: check.message },
      ...(location
        ? {
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: location.uri },
                  ...(location.line ? { region: { startLine: location.line } } : {}),
                },
              },
            ],
          }
        : {}),
      properties: { status: check.status },
    };
  });

  const toolErrors = findings
    .filter((check) => check.status === 'TOOL_ERROR')
    .map((check) => ({ level: 'error' as const, message: { text: check.message } }));

  const log = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'cap-release-guard',
            version: VERSION,
            informationUri: 'https://github.com/hxing7482-blip/cap-release-guard',
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: toolErrors.length === 0,
            ...(toolErrors.length > 0 ? { toolExecutionNotifications: toolErrors } : {}),
          },
        ],
        results,
      },
    ],
  };

  return JSON.stringify(log, null, 2);
}
