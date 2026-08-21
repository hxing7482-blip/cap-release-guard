import { describe, expect, it } from 'vitest';
import { renderJson } from '../src/reporting/json.js';
import { renderMarkdown } from '../src/reporting/markdown.js';
import { createResult } from '../src/rules/result.js';

const result = createResult([
  { id: 'sample.check', status: 'PASS', message: 'Synthetic check passed.' },
]);

describe('reporters', () => {
  it('renders the JSON result schema', () => {
    const parsed = JSON.parse(renderJson(result)) as Record<string, unknown>;
    expect(parsed.status).toBe('PASS');
    expect(parsed).toHaveProperty('checks');
    expect(parsed).toHaveProperty('summary');
  });

  it('renders a Markdown report', () => {
    const markdown = renderMarkdown(result);
    expect(markdown).toContain('# cap-release-guard report');
    expect(markdown).toContain('| PASS | sample.check |');
  });
});
