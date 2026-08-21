import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { inspectAndroidNetworkSecurity } from '../src/android/network-security.js';
import { RULE_IDS } from '../src/rules/ids.js';

const temporaryDirectories: string[] = [];

interface ProjectFiles {
  mainManifest: string;
  releaseManifest?: string;
  mainNetwork?: string;
  releaseNetwork?: string;
}

async function createProject(files: ProjectFiles): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'crg-network-synthetic-'));
  temporaryDirectories.push(root);
  const main = join(root, 'android', 'app', 'src', 'main');
  await mkdir(main, { recursive: true });
  await writeFile(join(main, 'AndroidManifest.xml'), files.mainManifest);

  if (files.releaseManifest) {
    const release = join(root, 'android', 'app', 'src', 'release');
    await mkdir(release, { recursive: true });
    await writeFile(join(release, 'AndroidManifest.xml'), files.releaseManifest);
  }
  if (files.mainNetwork) {
    const directory = join(main, 'res', 'xml');
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, 'network_security_config.xml'), files.mainNetwork);
  }
  if (files.releaseNetwork) {
    const directory = join(root, 'android', 'app', 'src', 'release', 'res', 'xml');
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, 'network_security_config.xml'), files.releaseNetwork);
  }
  return root;
}

function manifest(attributes = ''): string {
  return `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application ${attributes} />
</manifest>`;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true }))
  );
});

describe('Android network security checks', () => {
  it('blocks usesCleartextTraffic=true with a relative location', async () => {
    const root = await createProject({
      mainManifest: manifest('android:usesCleartextTraffic="true"'),
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: RULE_IDS.androidCleartextTraffic,
          status: 'BLOCKED',
          location: expect.stringMatching(/^android\/app\/src\/main\/AndroidManifest\.xml:\d+$/),
        }),
      ])
    );
  });

  it('passes usesCleartextTraffic=false', async () => {
    const root = await createProject({
      mainManifest: manifest('android:usesCleartextTraffic="false"'),
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks.find((check) => check.id === RULE_IDS.androidCleartextTraffic)?.status).toBe(
      'PASS'
    );
  });

  it('does not fail an absent usesCleartextTraffic attribute', async () => {
    const root = await createProject({ mainManifest: manifest() });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks.find((check) => check.id === RULE_IDS.androidCleartextTraffic)?.status).toBe(
      'PASS'
    );
  });

  it('blocks base-config cleartextTrafficPermitted=true', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <base-config cleartextTrafficPermitted="true" />
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: RULE_IDS.androidNetworkSecurityCleartext,
          status: 'BLOCKED',
        }),
      ])
    );
  });

  it('reports a minimal domain for domain-config cleartext', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">public.example</domain>
  </domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: RULE_IDS.androidNetworkSecurityCleartext,
          status: 'BLOCKED',
          details: { domain: 'public.example' },
        }),
      ])
    );
    expect(JSON.stringify(checks)).not.toContain('<domain-config');
  });

  it('passes an explicitly safe network security configuration', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(
      checks.find((check) => check.id === RULE_IDS.androidNetworkSecurityCleartext)?.status
    ).toBe('PASS');
  });

  it('does not mechanically block debug-overrides', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <debug-overrides>
    <trust-anchors><certificates src="user" /></trust-anchors>
  </debug-overrides>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks.some((check) => check.status === 'BLOCKED')).toBe(false);
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'android.network-security.debug-overrides',
          status: 'PASS',
        }),
      ])
    );
  });

  it('uses a release manifest attribute in preference to main', async () => {
    const root = await createProject({
      mainManifest: manifest('android:usesCleartextTraffic="true"'),
      releaseManifest: manifest('android:usesCleartextTraffic="false"'),
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks.find((check) => check.id === RULE_IDS.androidCleartextTraffic)?.status).toBe(
      'PASS'
    );
  });

  it('uses a release XML resource in preference to main', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork:
        '<network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>',
      releaseNetwork:
        '<network-security-config><base-config cleartextTrafficPermitted="false" /></network-security-config>',
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(
      checks.find((check) => check.id === RULE_IDS.androidNetworkSecurityCleartext)?.status
    ).toBe('PASS');
  });
});
