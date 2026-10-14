import { hash, verify } from '@node-rs/argon2';

// @node-rs/argon2 uses Argon2id by default, with parameters that meet current OWASP guidance.
export function hashPassword(password: string): Promise<string> {
  return hash(password);
}

export async function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false; // malformed hash: treat as a failed login, never as a crash
  }
}

// Used when the email is unknown, so that a login attempt takes about the same time whether or
// not the account exists (prevents discovering accounts through response time).
const dummyHash = await hash('dummy-password-used-for-timing-only');
export async function verifyAgainstDummy(password: string): Promise<void> {
  await verifyPassword(dummyHash, password);
}
