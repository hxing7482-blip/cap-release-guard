import { describe, expect, it } from 'vitest';
import { renderSarif } from '../src/reporting/sarif.js';
import { createResult, toolError } from '../src/rules/result.js';

function parseSarif(result: ReturnType<typeof createResult>): Record<string, unknown> {
  return JSON.parse(renderSarif(result)) as Record<string, unknown>;
}

function firstRun(result: ReturnType<typeof createResult>): Record<string, unknown> {
  const log = parseSarif(result);
  return (log.runs as Array<Record<string, unknown>>)[0] ?? {};
}

describe('SARIF reporting', () => {
  it('renders SARIF 2.1.0 schema basics', () => {
    const log = parseSarif(
      createResult([{ id: 'sample.warn', status: 'WARN', message: 'Synthetic warning.' }])
    );
    expect(log.version).toBe('2.1.0');
    expect(log.$schema).toContain('sarif-2.1.0');
    expect(log.runs).toHaveLength(1);
    expect(firstRun(createResult([]))).toHaveProperty('tool');
  });

  it('does not emit findings for passing checks', () => {
    const run = firstRun(
      createResult([{ id: 'sample.pass', status: 'PASS', message: 'Synthetic pass.' }])
    );
    expect(run.results).toEqual([]);
  });

  it('maps WARN to warning', () => {
    const run = firstRun(
      createResult([{ id: 'sample.warn', status: 'WARN', message: 'Synthetic warning.' }])
    );
    expect(run.results).toEqual([
      expect.objectContaining({ ruleId: 'sample.warn', level: 'warning' }),
    ]);
  });

  it('maps BLOCKED to error', () => {
    const run = firstRun(
      createResult([{ id: 'sample.blocked', status: 'BLOCKED', message: 'Synthetic block.' }])
    );
    expect(run.results).toEqual([
      expect.objectContaining({ ruleId: 'sample.blocked', level: 'error' }),
    ]);
  });

  it('emits relative locations and line numbers', () => {
    const run = firstRun(
      createResult([
        {
          id: 'sample.location',
          status: 'WARN',
          message: 'Synthetic location.',
          location: 'android/app/src/main/AndroidManifest.xml:7',
        },
      ])
    );
    const result = (run.results as Array<Record<string, unknown>>)[0];
    expect(result).toMatchObject({
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: 'android/app/src/main/AndroidManifest.xml' },
            region: { startLine: 7 },
          },
        },
      ],
    });
  });

  it('does not leak an absolute Windows path', () => {
    const absolutePath = ['C:', 'synthetic', 'project', 'AndroidManifest.xml'].join('\\');
    const output = renderSarif(
      createResult([
        {
          id: 'sample.absolute',
          status: 'WARN',
          message: 'Synthetic path.',
          location: `${absolutePath}:4`,
        },
      ])
    );
    expect(output).not.toContain(absolutePath);
    expect(output).toContain('AndroidManifest.xml');
  });

  it('is deterministic for identical findings', () => {
    const result = createResult([
      { id: 'sample.z', status: 'WARN', message: 'Z.' },
      { id: 'sample.a', status: 'BLOCKED', message: 'A.' },
    ]);
    expect(renderSarif(result)).toBe(renderSarif(result));
    expect(renderSarif(result).indexOf('sample.a')).toBeLessThan(
      renderSarif(result).indexOf('sample.z')
    );
  });

  it('reports TOOL_ERROR as an execution notification', () => {
    const run = firstRun(toolError('sample.tool', 'Synthetic tool error.'));
    expect(run.invocations).toEqual([
      expect.objectContaining({
        executionSuccessful: false,
        toolExecutionNotifications: [
          expect.objectContaining({ level: 'error', message: { text: 'Synthetic tool error.' } }),
        ],
      }),
    ]);
  });
});
