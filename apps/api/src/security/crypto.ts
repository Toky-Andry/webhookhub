import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = 'v1';
const IV_BYTES = 12; // recommended size for AES-GCM
const TAG_BYTES = 16;

export function parseEncryptionKey(base64: string): Buffer {
  const key = Buffer.from(base64, 'base64');
  if (key.length !== 32) throw new Error('ENCRYPTION_KEY must be 32 bytes, encoded in base64');
  return key;
}

/**
 * Encrypts a secret with AES-256-GCM. The "context" (for example the endpoint id) is
 * authenticated but not encrypted: a ciphertext copied to another row will fail to decrypt.
 * Format: v1:base64(iv | tag | ciphertext)
 */
export function encryptSecret(plaintext: string, key: Buffer, context: string): string {
  const iv = randomBytes(IV_BYTES); // a new random IV every time
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return `${VERSION}:${Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64')}`;
}

export function decryptSecret(stored: string, key: Buffer, context: string): string {
  const [version, payload] = stored.split(':');
  if (version !== VERSION || !payload) throw new Error('Unsupported secret format');
  const raw = Buffer.from(payload, 'base64');
  const iv = raw.subarray(0, IV_BYTES);
  const tag = raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const ciphertext = raw.subarray(IV_BYTES + TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}
