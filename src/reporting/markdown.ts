import type { AuditResult } from '../types.js';

function escapeCell(value: unknown): string {
  return String(value).replaceAll('|', '\\|').replaceAll('\n', ' ');
}

export function renderMarkdown(result: AuditResult): string {
  const lines = [
    '# cap-release-guard report',
    '',
    `**Status:** ${result.status}`,
    '',
    `**Summary:** ${result.summary.pass} pass · ${result.summary.warn} warn · ${result.summary.blocked} blocked · ${result.summary.toolError} tool error`,
    '',
    '| Status | Check | Location | Message |',
    '| --- | --- | --- | --- |',
  ];

  for (const check of result.checks) {
    lines.push(
      `| ${check.status} | ${escapeCell(check.id)} | ${escapeCell(check.location ?? '')} | ${escapeCell(check.message)} |`
    );
    if (check.details) {
      const details = Object.entries(check.details)
        .map(([key, value]) => `${key}=${String(value)}`)
        .join(', ');
      lines.push(`|  | details |  | ${escapeCell(details)} |`);
    }
  }

  return lines.join('\n');
}
