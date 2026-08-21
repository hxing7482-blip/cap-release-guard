import { describe, expect, it } from 'vitest';
import { scanEndpointContent } from '../src/endpoints/scanner.js';

describe('endpoint scanning', () => {
  it('detects localhost only in endpoint-like URL context', () => {
    expect(scanEndpointContent('const api = "http://localhost:3000/v1";', 'app.js')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: 'local-endpoint-url', severity: 'BLOCKED' }),
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

  it('detects cleartext HTTP endpoints', () => {
    expect(scanEndpointContent('fetch("http://example.com/v1")', 'bundle.js')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: 'cleartext-http-endpoint', severity: 'BLOCKED' }),
      ])
    );
  });
});
