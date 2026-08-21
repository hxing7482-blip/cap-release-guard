import type { AuditResult } from '../types.js';

export function renderJson(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}
