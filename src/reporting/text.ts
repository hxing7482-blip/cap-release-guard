import type { AuditResult } from '../types.js';

function formatDetails(details: Record<string, string | number | boolean | null>): string {
  return Object.entries(details)
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(', ');
}

export function renderText(result: AuditResult): string {
  const lines = [
    `Status: ${result.status}`,
    `Summary: ${result.summary.pass} pass, ${result.summary.warn} warn, ${result.summary.blocked} blocked, ${result.summary.toolError} tool error`,
    '',
  ];

  for (const check of result.checks) {
    const location = check.location ? ` (${check.location})` : '';
    lines.push(`[${check.status}] ${check.id}${location}: ${check.message}`);
    if (check.details) lines.push(`  ${formatDetails(check.details)}`);
  }

  return lines.join('\n').trimEnd();
}
