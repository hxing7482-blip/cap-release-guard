import type { AuditResult, OutputFormat } from '../types.js';
import { renderJson } from './json.js';
import { renderMarkdown } from './markdown.js';
import { renderSarif } from './sarif.js';
import { renderText } from './text.js';

export function isOutputFormat(value: string): value is OutputFormat {
  return value === 'text' || value === 'json' || value === 'markdown' || value === 'sarif';
}

export function render(result: AuditResult, format: OutputFormat): string {
  if (format === 'json') return renderJson(result);
  if (format === 'markdown') return renderMarkdown(result);
  if (format === 'sarif') return renderSarif(result);
  return renderText(result);
}
