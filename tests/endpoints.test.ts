import { describe, expect, it } from 'vitest';
import { scanEndpointContent } from '../src/endpoints/scanner.js';
import { RULE_IDS } from '../src/rules/ids.js';

describe('endpoint scanning', () => {
  it('detects localhost only in endpoint-like URL context', () => {
    expect(scanEndpointContent('const api = "http://localhost:3000/v1";', 'app.js')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: RULE_IDS.endpointLocalhost, severity: 'BLOCKED' }),
      ])
    );
    expect(
      scanEndpointContent('Documentation mentions localhost conceptually.', 'readme.txt')
    ).toEqual([]);
  });

  it('honors endpoint allowlist patterns', () => {
    const content = 'const preview = "https://sample.trycloudflare.com";';
    expect(scanEndpointContent(content, 'app.js')).toHaveLength(1);
    expect(scanEndpointContent(content, 'app.js', ['trycloudflare\\.com'])).toHaveLength(0);
  });

  it('detects cleartext HTTP endpoints with a stable rule ID', () => {
    expect(scanEndpointContent('fetch("http://example.com/v1")', 'bundle.js')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: RULE_IDS.endpointCleartextHttp, severity: 'BLOCKED' }),
      ])
    );
  });

  it('blocks an otherwise safe endpoint matched by the deny policy', () => {
    const findings = scanEndpointContent('fetch("https://blocked.example/v1")', 'bundle.js', {
      deny: ['blocked\\.example'],
    });
    expect(findings).toEqual([
      expect.objectContaining({ rule: RULE_IDS.endpointPolicyDeny, severity: 'BLOCKED' }),
    ]);
  });

  it('gives the active deny policy precedence over the active allow policy', () => {
    const findings = scanEndpointContent('fetch("https://shared.example/v1")', 'bundle.js', {
      allow: ['shared\\.example'],
      deny: ['shared\\.example'],
    });
    expect(findings).toEqual([
      expect.objectContaining({ rule: RULE_IDS.endpointPolicyDeny, severity: 'BLOCKED' }),
    ]);
  });
});
