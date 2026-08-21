import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { analyzeApk } from '../src/android/apk.js';
import { isAndroidDebugSigner } from '../src/android/apksigner.js';
import { compareCertificateIdentity } from '../src/android/compare.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true }))
  );
});

describe('Android safety rules', () => {
  it('classifies an Android Debug signer as unsafe', () => {
    expect(isAndroidDebugSigner('CN=Android Debug,O=Android,C=US')).toBe(true);
    expect(isAndroidDebugSigner('CN=Synthetic Release,O=Example')).toBe(false);
  });

  it('returns TOOL_ERROR for an invalid APK path', async () => {
    const result = await analyzeApk(join(tmpdir(), 'missing-synthetic.apk'), { tools: {} });
    expect(result.status).toBe('TOOL_ERROR');
    expect(result.checks[0]?.id).toBe('apk.path');
  });

  it('returns TOOL_ERROR when Android SDK tools are missing', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'crg-synthetic-'));
    temporaryDirectories.push(directory);
    const apk = join(directory, 'synthetic.apk');
    await writeFile(apk, 'synthetic fixture');
    const result = await analyzeApk(apk, { tools: {} });
    expect(result.status).toBe('TOOL_ERROR');
    expect(result.checks.map((check) => check.id)).toContain('apk.signature-tool');
  });

  it('reports certificate MATCH', () => {
    const md5 = 'AA'.repeat(16);
    const sha1 = 'BB'.repeat(20);
    const sha256 = 'CC'.repeat(32);
    const spki = 'DD'.repeat(32);
    expect(
      compareCertificateIdentity(
        { md5, sha1, sha256, publicKeySha256: spki },
        { md5, sha1, sha256, spkiSha256: spki }
      )
    ).toEqual({ outcome: 'MATCH', mismatches: [] });
  });

  it('reports certificate MISMATCH', () => {
    const md5 = 'AA'.repeat(16);
    const sha1 = 'BB'.repeat(20);
    const sha256 = 'CC'.repeat(32);
    const result = compareCertificateIdentity(
      { md5, sha1, sha256, publicKeySha256: 'DD'.repeat(32) },
      { md5, sha1, sha256: 'EE'.repeat(32), spkiSha256: 'DD'.repeat(32) }
    );
    expect(result.outcome).toBe('MISMATCH');
    expect(result.mismatches).toContain('Certificate SHA256');
  });
});
