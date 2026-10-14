import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decryptSecret, encryptSecret, parseEncryptionKey } from './crypto.js';

const key = randomBytes(32);

describe('secret encryption', () => {
  it('encrypts and decrypts', () => {
    const stored = encryptSecret('whsec_abc123', key, 'endpoint-1');
    expect(stored).not.toContain('whsec_abc123');
    expect(decryptSecret(stored, key, 'endpoint-1')).toBe('whsec_abc123');
  });

  it('uses a different IV every time', () => {
    expect(encryptSecret('same', key, 'ctx')).not.toBe(encryptSecret('same', key, 'ctx'));
  });

  it('refuses a ciphertext moved to another context (another endpoint)', () => {
    const stored = encryptSecret('whsec_abc123', key, 'endpoint-1');
    expect(() => decryptSecret(stored, key, 'endpoint-2')).toThrow();
  });

  it('detects tampering and the wrong key', () => {
    const stored = encryptSecret('whsec_abc123', key, 'ctx');
    const bytes = Buffer.from(stored.slice(3), 'base64');
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    expect(() => decryptSecret(`v1:${bytes.toString('base64')}`, key, 'ctx')).toThrow();
    expect(() => decryptSecret(stored, randomBytes(32), 'ctx')).toThrow();
  });

  it('requires a 32-byte key', () => {
    expect(() => parseEncryptionKey(randomBytes(16).toString('base64'))).toThrow(/32 bytes/);
    expect(parseEncryptionKey(key.toString('base64'))).toHaveLength(32);
  });
});
