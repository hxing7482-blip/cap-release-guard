import type { AuditResult, Check, Status, Summary } from '../types.js';

const priority: Record<Status, number> = {
  PASS: 0,
  WARN: 1,
  TOOL_ERROR: 2,
  BLOCKED: 3,
};

export function aggregateStatus(checks: readonly Check[]): Status {
  if (checks.length === 0) return 'PASS';
  return checks.reduce<Status>(
    (current, check) => (priority[check.status] > priority[current] ? check.status : current),
    'PASS'
  );
}

export function summarize(checks: readonly Check[]): Summary {
  return checks.reduce<Summary>(
    (summary, check) => {
      if (check.status === 'PASS') summary.pass += 1;
      if (check.status === 'WARN') summary.warn += 1;
      if (check.status === 'BLOCKED') summary.blocked += 1;
      if (check.status === 'TOOL_ERROR') summary.toolError += 1;
      return summary;
    },
    { pass: 0, warn: 0, blocked: 0, toolError: 0 }
  );
}

export function createResult(checks: Check[]): AuditResult {
  return {
    status: aggregateStatus(checks),
    checks,
    summary: summarize(checks),
  };
}

export function exitCodeFor(status: Status): number {
  const codes: Record<Status, number> = {
    PASS: 0,
    WARN: 1,
    BLOCKED: 2,
    TOOL_ERROR: 3,
  };
  return codes[status];
}

export function toolError(id: string, message: string): AuditResult {
  return createResult([{ id, status: 'TOOL_ERROR', message }]);
}
