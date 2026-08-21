import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  applyReleasePolicy,
  parseReleaseGuardConfig,
  resolveReleasePolicy,
} from '../src/config/policy.js';
import { RULE_IDS } from '../src/rules/ids.js';
import { createResult } from '../src/rules/result.js';

const temporaryDirectories: string[] = [];

async function temporaryProject(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'crg-config-synthetic-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true }))
  );
});

describe('release policy configuration', () => {
  it('parses a valid versioned configuration and canonicalizes documented aliases', () => {
    const parsed = parseReleaseGuardConfig(
      JSON.stringify({
        version: 1,
        endpoints: { allow: ['approved\\.example'], deny: ['blocked\\.example'] },
        rules: { 'android.debugSigner': 'blocked', 'endpoint.cleartextHttp': 'warn' },
      })
    );
    expect(parsed).toMatchObject({
      ok: true,
      policy: {
        endpointAllow: ['approved\\.example'],
        endpointDeny: ['blocked\\.example'],
        rules: {
          [RULE_IDS.androidDebugSigner]: 'blocked',
          [RULE_IDS.endpointCleartextHttp]: 'warn',
        },
      },
    });
  });

  it('rejects invalid JSON', () => {
    expect(parseReleaseGuardConfig('{ invalid')).toEqual({
      ok: false,
      message: 'Configuration must contain valid JSON.',
    });
  });

  it('rejects unsupported configuration versions', () => {
    expect(parseReleaseGuardConfig(JSON.stringify({ version: 2 }))).toEqual({
      ok: false,
      message: 'Configuration version must be 1.',
    });
  });

  it('returns TOOL_ERROR for an invalid project configuration', async () => {
    const directory = await temporaryProject();
    await writeFile(join(directory, '.releaseguard.json'), '{ invalid');
    const resolution = await resolveReleasePolicy({ cwd: directory });
    expect(resolution.ok).toBe(false);
    if (!resolution.ok) {
      expect(resolution.result.status).toBe('TOOL_ERROR');
      expect(resolution.result.checks[0]?.id).toBe('config.invalid');
    }
  });

  it('preserves v0.1 defaults when no configuration exists', async () => {
    const directory = await temporaryProject();
    const resolution = await resolveReleasePolicy({ cwd: directory });
    expect(resolution).toMatchObject({
      ok: true,
      policy: { endpointAllow: [], endpointDeny: [], rules: {} },
    });
  });

  it('uses CLI endpoint patterns instead of configured patterns when provided', async () => {
    const directory = await temporaryProject();
    await writeFile(
      join(directory, '.releaseguard.json'),
      JSON.stringify({
        version: 1,
        endpoints: { allow: ['configured-allow'], deny: ['configured-deny'] },
      })
    );
    const resolution = await resolveReleasePolicy({
      cwd: directory,
      cli: { allow: ['cli-allow-one', 'cli-allow-two'], deny: ['cli-deny'] },
    });
    expect(resolution).toMatchObject({
      ok: true,
      policy: {
        endpointAllow: ['cli-allow-one', 'cli-allow-two'],
        endpointDeny: ['cli-deny'],
      },
    });
  });

  it('gives CLI rule overrides precedence over configuration', async () => {
    const directory = await temporaryProject();
    await writeFile(
      join(directory, '.releaseguard.json'),
      JSON.stringify({ version: 1, rules: { 'endpoint.cleartext-http': 'blocked' } })
    );
    const resolution = await resolveReleasePolicy({
      cwd: directory,
      cli: { rules: ['endpoint.cleartext-http=warn'] },
    });
    expect(resolution).toMatchObject({
      ok: true,
      policy: { rules: { [RULE_IDS.endpointCleartextHttp]: 'warn' } },
    });
  });

  it('applies severity overrides and recomputes the aggregate result', () => {
    const result = createResult([
      {
        id: RULE_IDS.endpointCleartextHttp,
        status: 'BLOCKED',
        message: 'Synthetic cleartext endpoint.',
      },
    ]);
    const overridden = applyReleasePolicy(result, {
      endpointAllow: [],
      endpointDeny: [],
      rules: { [RULE_IDS.endpointCleartextHttp]: 'warn' },
    });
    expect(overridden.status).toBe('WARN');
    expect(overridden.checks[0]?.status).toBe('WARN');
  });

  it('supports explicitly disabling a finding rule', () => {
    const result = createResult([
      {
        id: RULE_IDS.endpointTunnel,
        status: 'BLOCKED',
        message: 'Synthetic tunnel endpoint.',
      },
    ]);
    const overridden = applyReleasePolicy(result, {
      endpointAllow: [],
      endpointDeny: [],
      rules: { [RULE_IDS.endpointTunnel]: 'off' },
    });
    expect(overridden.status).toBe('PASS');
    expect(overridden.checks[0]).toMatchObject({ status: 'PASS' });
  });
});
