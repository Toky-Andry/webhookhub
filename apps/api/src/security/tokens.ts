import { createHash, randomBytes } from 'node:crypto';

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export const API_KEY_PREFIX = 'whk_live_';
/** Characters shown in the dashboard to recognize a key: "whk_live_" plus 4 characters. */
const DISPLAY_PREFIX_LENGTH = API_KEY_PREFIX.length + 4;

export interface GeneratedApiKey {
  /** The full key. Shown once to the user and never stored. */
  key: string;
  prefix: string;
  /** What is stored in the database. */
  hash: string;
}

export function generateApiKey(): GeneratedApiKey {
  const key = `${API_KEY_PREFIX}${randomToken(32)}`; // 256 bits of randomness
  return { key, prefix: key.slice(0, DISPLAY_PREFIX_LENGTH), hash: sha256Hex(key) };
}
