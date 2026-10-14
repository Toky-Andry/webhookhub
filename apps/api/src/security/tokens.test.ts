import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword } from './password.js';
import { generateApiKey, sha256Hex } from './tokens.js';

describe('API keys', () => {
  it('generates a prefixed, random key and its hash', () => {
    const a = generateApiKey();
    const b = generateApiKey();
    expect(a.key).toMatch(/^whk_live_[A-Za-z0-9_-]{43}$/);
    expect(a.key).not.toBe(b.key);
    expect(a.prefix).toBe(a.key.slice(0, 13));
    expect(a.hash).toBe(sha256Hex(a.key));
    expect(a.hash).not.toContain(a.key);
  });
});

describe('passwords', () => {
  it('hashes with Argon2id and verifies', async () => {
    const hash = await hashPassword('correct-horse-battery-staple');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword(hash, 'correct-horse-battery-staple')).toBe(true);
    expect(await verifyPassword(hash, 'wrong-password-123')).toBe(false);
  });

  it('treats a malformed hash as a failed verification', async () => {
    expect(await verifyPassword('not-a-hash', 'anything')).toBe(false);
  });
});
