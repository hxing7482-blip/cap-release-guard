import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { inspectAndroidNetworkSecurity } from '../src/android/network-security.js';
import { RULE_IDS } from '../src/rules/ids.js';
import type { Check } from '../src/types.js';

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

function cleartextBlocks(checks: Check[]): Check[] {
  return checks.filter(
    (check) => check.id === RULE_IDS.androidNetworkSecurityCleartext && check.status === 'BLOCKED'
  );
}

function blockedDomains(checks: Check[]): string[] {
  return cleartextBlocks(checks)
    .map((check) => check.details?.domain)
    .filter((domain): domain is string => typeof domain === 'string')
    .sort();
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
          details: { domain: 'public.example', includeSubdomains: true },
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

  it('lets a nested child disable cleartext inherited from an unsafe parent', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">example.com</domain>
    <domain-config cleartextTrafficPermitted="false">
      <domain>secure.example.com</domain>
    </domain-config>
  </domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(blockedDomains(checks)).toEqual(['example.com']);
  });

  it('inherits unsafe cleartext into a nested child without an explicit value', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain>parent.example</domain>
    <domain-config>
      <domain>child.parent.example</domain>
    </domain-config>
  </domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(blockedDomains(checks)).toEqual(['child.parent.example', 'parent.example']);
  });

  it('lets a nested child enable cleartext under a safe parent', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain>safe.example</domain>
    <domain-config cleartextTrafficPermitted="true">
      <domain>unsafe.safe.example</domain>
    </domain-config>
  </domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(blockedDomains(checks)).toEqual(['unsafe.safe.example']);
  });

  it('inherits base-config cleartext into a top-level domain-config', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <base-config cleartextTrafficPermitted="true" />
  <domain-config>
    <domain>inherited.example</domain>
  </domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(blockedDomains(checks)).toEqual(['inherited.example']);
  });

  it('applies base, parent, and child overrides in order', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true">
    <domain>parent-unsafe.example</domain>
    <domain-config cleartextTrafficPermitted="false">
      <domain>child-safe.parent-unsafe.example</domain>
    </domain-config>
  </domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(blockedDomains(checks)).toEqual(['parent-unsafe.example']);
  });

  it('inherits cleartext through three nested domain-config levels', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true">
    <domain>level-one.example</domain>
    <domain-config>
      <domain>level-two.level-one.example</domain>
      <domain-config>
        <domain>level-three.level-two.level-one.example</domain>
      </domain-config>
    </domain-config>
  </domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(blockedDomains(checks)).toEqual([
      'level-one.example',
      'level-three.level-two.level-one.example',
      'level-two.level-one.example',
    ]);
  });

  it('excludes nested domain-config content inside debug-overrides', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <debug-overrides>
    <domain-config cleartextTrafficPermitted="true">
      <domain>debug-only.example</domain>
    </domain-config>
  </debug-overrides>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(cleartextBlocks(checks)).toHaveLength(0);
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'android.network-security.debug-overrides',
          status: 'PASS',
        }),
      ])
    );
  });

  it('ignores fake domain-config markup inside XML comments', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <!-- <domain-config cleartextTrafficPermitted="true"><domain>fake.example</domain></domain-config> -->
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(cleartextBlocks(checks)).toHaveLength(0);
    expect(JSON.stringify(checks)).not.toContain('fake.example');
  });

  it('returns a safe TOOL_ERROR for a DTD declaration', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<!DOCTYPE network-security-config>
<network-security-config>
  <domain-config cleartextTrafficPermitted="true"><domain>dtd-marker.example</domain></domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'android.network-security.xml', status: 'TOOL_ERROR' }),
      ])
    );
    expect(JSON.stringify(checks)).not.toContain('dtd-marker.example');
  });

  it('returns a safe TOOL_ERROR without expanding a declared entity', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<!DOCTYPE network-security-config [
  <!ENTITY unsafe "entity-marker.example">
]>
<network-security-config>
  <domain-config cleartextTrafficPermitted="true"><domain>&unsafe;</domain></domain-config>
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'android.network-security.xml', status: 'TOOL_ERROR' }),
      ])
    );
    expect(JSON.stringify(checks)).not.toContain('entity-marker.example');
    expect(JSON.stringify(checks)).not.toContain('&unsafe;');
  });

  it('returns TOOL_ERROR instead of processing XInclude', async () => {
    const root = await createProject({
      mainManifest: manifest('android:networkSecurityConfig="@xml/network_security_config"'),
      mainNetwork: `<network-security-config xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="https://invalid.example/network.xml" />
</network-security-config>`,
    });
    const checks = await inspectAndroidNetworkSecurity(root);
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'android.network-security.xml', status: 'TOOL_ERROR' }),
      ])
    );
    expect(JSON.stringify(checks)).not.toContain('invalid.example');
  });
});
