export type Status = 'PASS' | 'WARN' | 'BLOCKED' | 'TOOL_ERROR';

export type SafeDetailValue = string | number | boolean | null;

export interface Check {
  id: string;
  status: Status;
  message: string;
  location?: string;
  details?: Record<string, SafeDetailValue>;
}

export interface Summary {
  pass: number;
  warn: number;
  blocked: number;
  toolError: number;
}

export interface AuditResult {
  status: Status;
  checks: Check[];
  summary: Summary;
}

export type OutputFormat = 'text' | 'json' | 'markdown' | 'sarif';
