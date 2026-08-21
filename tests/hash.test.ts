import { describe, expect, it } from 'vitest';
import { normalizeMd5, normalizeSha1, normalizeSha256 } from '../src/utils/hash.js';

describe('fingerprint normalization', () => {
  it('normalizes MD5', () => {
    expect(normalizeMd5('aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99')).toBe(
      'AABBCCDDEEFF00112233445566778899'
    );
  });

  it('normalizes SHA1', () => {
    expect(normalizeSha1('aa '.repeat(20))).toBe('AA'.repeat(20));
  });

  it('normalizes SHA256', () => {
    expect(normalizeSha256('ab:'.repeat(31) + 'ab')).toBe('AB'.repeat(32));
  });
});
