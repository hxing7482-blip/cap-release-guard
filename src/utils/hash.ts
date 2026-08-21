export function normalizeFingerprint(value: string): string {
  return value.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
}

export function normalizeMd5(value: string): string {
  const normalized = normalizeFingerprint(value);
  if (normalized.length !== 32) throw new Error('Invalid MD5 fingerprint.');
  return normalized;
}

export function normalizeSha1(value: string): string {
  const normalized = normalizeFingerprint(value);
  if (normalized.length !== 40) throw new Error('Invalid SHA1 fingerprint.');
  return normalized;
}

export function normalizeSha256(value: string): string {
  const normalized = normalizeFingerprint(value);
  if (normalized.length !== 64) throw new Error('Invalid SHA256 fingerprint.');
  return normalized;
}
