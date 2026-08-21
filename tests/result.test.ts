import { describe, expect, it } from 'vitest';
import { aggregateStatus, createResult, exitCodeFor } from '../src/rules/result.js';
import type { Check } from '../src/types.js';

const check = (status: Check['status']): Check => ({
  id: status.toLowerCase(),
  status,
  message: status,
});

describe('result aggregation', () => {
  it('aggregates PASS', () => {
    expect(createResult([check('PASS')])).toMatchObject({
      status: 'PASS',
      summary: { pass: 1, warn: 0, blocked: 0 },
    });
  });

  it('aggregates WARN', () => {
    expect(aggregateStatus([check('PASS'), check('WARN')])).toBe('WARN');
  });

  it('aggregates BLOCKED', () => {
    expect(aggregateStatus([check('PASS'), check('WARN'), check('BLOCKED')])).toBe('BLOCKED');
  });

  it('maps statuses to documented exit codes', () => {
    expect(exitCodeFor('PASS')).toBe(0);
    expect(exitCodeFor('WARN')).toBe(1);
    expect(exitCodeFor('BLOCKED')).toBe(2);
    expect(exitCodeFor('TOOL_ERROR')).toBe(3);
  });
});
