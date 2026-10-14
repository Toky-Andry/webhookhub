import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiKeys, memberships, sessions, users } from '../db/schema.js';
import { sha256Hex } from '../security/tokens.js';
import {
  captureLogs,
  createTestApp,
  createTestDb,
  registerUser,
  STRONG_PASSWORD,
  uniqueEmail,
  type TestApp,
  type TestDb,
} from '../test/helpers.js';
import { SESSION_COOKIE } from './plugin.js';

let db: TestDb;
let closeDb: () => Promise<void>;
let app: TestApp;

beforeAll(async () => {
  const created = await createTestDb();
  db = created.db;
  closeDb = created.close;
  app = await createTestApp(db);
}, 60_000);

afterAll(async () => {
  await app.close();
  await closeDb();
});

async function createKey(cookieHeader: string, name = 'Production worker') {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/api-keys',
    headers: { cookie: cookieHeader },
    payload: { name },
  });
  return { res, body: res.json() as { id: string; key: string; prefix: string } };
}

describe('registration', () => {
  it('creates the user, the organization and an owner membership, and starts a session', async () => {
    const { res, body, cookie } = await registerUser(app);
    expect(res.statusCode).toBe(201);
    expect(cookie?.httpOnly).toBe(true);
    expect(cookie?.sameSite).toBe('Lax');

    const [member] = await db
      .select()
      .from(memberships)
      .where(eq(memberships.userId, body.user.id));
    expect(member?.role).toBe('owner');
    expect(member?.organizationId).toBe(body.organization.id);
  });

  it('never stores the password in clear text', async () => {
    const { body } = await registerUser(app);
    const [user] = await db.select().from(users).where(eq(users.id, body.user.id));
    expect(user?.passwordHash.startsWith('$argon2id$')).toBe(true);
    expect(user?.passwordHash).not.toContain(STRONG_PASSWORD);
  });

  it('stores only a hash of the session token', async () => {
    const { cookie, body } = await registerUser(app);
    const [row] = await db.select().from(sessions).where(eq(sessions.userId, body.user.id));
    expect(row?.tokenHash).toBe(sha256Hex(cookie!.value));
    expect(row?.tokenHash).not.toBe(cookie!.value);
  });

  it.each([
    ['a short password', { password: 'short' }],
    ['an invalid email', { email: 'not-an-email' }],
    ['an empty organization name', { organizationName: ' ' }],
  ])('rejects %s', async (_label, override) => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: uniqueEmail(),
        password: STRONG_PASSWORD,
        organizationName: 'Acme',
        ...override,
      },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects a duplicate email, whatever its case', async () => {
    const first = await registerUser(app, { email: 'Same.Person@Example.com' });
    expect(first.res.statusCode).toBe(201);
    const second = await registerUser(app, { email: 'same.person@example.COM' });
    expect(second.res.statusCode).toBe(409);
  });
});

describe('login and sessions', () => {
  it('logs in with the right password', async () => {
    const { email } = await registerUser(app);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email, password: STRONG_PASSWORD },
    });
    expect(res.statusCode).toBe(200);
    expect(res.cookies.some((c) => c.name === SESSION_COOKIE)).toBe(true);
  });

  it('gives the same answer for an unknown email and a wrong password', async () => {
    const { email } = await registerUser(app);
    const wrongPassword = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email, password: 'definitely-not-the-password' },
    });
    const unknownEmail = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email: 'nobody@example.com', password: 'definitely-not-the-password' },
    });
    expect(wrongPassword.statusCode).toBe(401);
    expect(unknownEmail.statusCode).toBe(401);
    expect(unknownEmail.body).toBe(wrongPassword.body);
  });

  it('requires a session for /v1/auth/me', async () => {
    const anonymous = await app.inject({ method: 'GET', url: '/v1/auth/me' });
    expect(anonymous.statusCode).toBe(401);

    const { cookieHeader, email } = await registerUser(app);
    const res = await app.inject({
      method: 'GET',
      url: '/v1/auth/me',
      headers: { cookie: cookieHeader },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().user.email).toBe(email);
    expect(res.json().role).toBe('owner');
  });

  it('rejects a forged session cookie', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/auth/me',
      headers: { cookie: `${SESSION_COOKIE}=forged-token-value` },
    });
    expect(res.statusCode).toBe(401);
  });

  it('logout invalidates the session', async () => {
    const { cookieHeader } = await registerUser(app);
    const out = await app.inject({
      method: 'POST',
      url: '/v1/auth/logout',
      headers: { cookie: cookieHeader },
    });
    expect(out.statusCode).toBe(204);
    const me = await app.inject({
      method: 'GET',
      url: '/v1/auth/me',
      headers: { cookie: cookieHeader },
    });
    expect(me.statusCode).toBe(401);
  });

  it('rejects an expired session', async () => {
    const { cookieHeader, body } = await registerUser(app);
    await db
      .update(sessions)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(sessions.userId, body.user.id));
    const res = await app.inject({
      method: 'GET',
      url: '/v1/auth/me',
      headers: { cookie: cookieHeader },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('API keys', () => {
  it('returns the full key once, and stores only its hash', async () => {
    const { cookieHeader } = await registerUser(app);
    const { res, body } = await createKey(cookieHeader);
    expect(res.statusCode).toBe(201);
    expect(body.key).toMatch(/^whk_live_/);

    const [row] = await db.select().from(apiKeys).where(eq(apiKeys.id, body.id));
    expect(row?.keyHash).toBe(sha256Hex(body.key));
    expect(JSON.stringify(row)).not.toContain(body.key);

    const list = await app.inject({
      method: 'GET',
      url: '/v1/api-keys',
      headers: { cookie: cookieHeader },
    });
    expect(list.statusCode).toBe(200);
    expect(list.body).not.toContain(body.key);
    expect(list.body).not.toContain(row!.keyHash);
    expect(list.json().keys[0].prefix).toBe(body.prefix);
  });

  it('requires a session to create or list keys', async () => {
    const create = await app.inject({
      method: 'POST',
      url: '/v1/api-keys',
      payload: { name: 'x' },
    });
    const list = await app.inject({ method: 'GET', url: '/v1/api-keys' });
    expect(create.statusCode).toBe(401);
    expect(list.statusCode).toBe(401);
  });

  it('authenticates an application with a valid key', async () => {
    const { cookieHeader, body: account } = await registerUser(app);
    const { body } = await createKey(cookieHeader);
    const res = await app.inject({
      method: 'GET',
      url: '/v1/whoami',
      headers: { authorization: `Bearer ${body.key}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().organizationId).toBe(account.organization.id);
  });

  it.each([
    ['no header', undefined],
    ['a wrong scheme', 'Basic abc'],
    ['an unknown key', 'Bearer whk_live_this-key-does-not-exist'],
  ])('rejects %s', async (_label, authorization) => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/whoami',
      headers: authorization ? { authorization } : {},
    });
    expect(res.statusCode).toBe(401);
  });

  it('stops accepting a key once it is revoked', async () => {
    const { cookieHeader } = await registerUser(app);
    const { body } = await createKey(cookieHeader);
    const headers = { authorization: `Bearer ${body.key}` };

    expect((await app.inject({ method: 'GET', url: '/v1/whoami', headers })).statusCode).toBe(200);

    const revoke = await app.inject({
      method: 'DELETE',
      url: `/v1/api-keys/${body.id}`,
      headers: { cookie: cookieHeader },
    });
    expect(revoke.statusCode).toBe(204);

    expect((await app.inject({ method: 'GET', url: '/v1/whoami', headers })).statusCode).toBe(401);
  });

  it('refuses to create a key for a viewer', async () => {
    const owner = await registerUser(app);
    const viewer = await registerUser(app);
    // Make the second user a viewer of the first organization only.
    await db.delete(memberships).where(eq(memberships.userId, viewer.body.user.id));
    await db.insert(memberships).values({
      userId: viewer.body.user.id,
      organizationId: owner.body.organization.id,
      role: 'viewer',
    });
    const { res } = await createKey(viewer.cookieHeader);
    expect(res.statusCode).toBe(403);
  });
});

describe('tenant isolation', () => {
  it("does not show another organization's keys", async () => {
    const a = await registerUser(app, { organizationName: 'Org A' });
    const b = await registerUser(app, { organizationName: 'Org B' });
    const { body: keyOfA } = await createKey(a.cookieHeader, 'Key of A');

    const listOfB = await app.inject({
      method: 'GET',
      url: '/v1/api-keys',
      headers: { cookie: b.cookieHeader },
    });
    expect(listOfB.json().keys).toEqual([]);
    expect(listOfB.body).not.toContain(keyOfA.id);
  });

  it("cannot revoke another organization's key", async () => {
    const a = await registerUser(app, { organizationName: 'Org A2' });
    const b = await registerUser(app, { organizationName: 'Org B2' });
    const { body: keyOfA } = await createKey(a.cookieHeader);

    const attempt = await app.inject({
      method: 'DELETE',
      url: `/v1/api-keys/${keyOfA.id}`,
      headers: { cookie: b.cookieHeader },
    });
    expect(attempt.statusCode).toBe(404);

    // The key of A still works.
    const stillValid = await app.inject({
      method: 'GET',
      url: '/v1/whoami',
      headers: { authorization: `Bearer ${keyOfA.key}` },
    });
    expect(stillValid.statusCode).toBe(200);
  });
});

describe('abuse protection', () => {
  it('rate-limits repeated login attempts', async () => {
    const limited = await createTestApp(db, {
      limits: {
        login: { max: 3, timeWindow: '1 minute' },
        register: { max: 1000, timeWindow: '1 minute' },
      },
    });
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await limited.inject({
        method: 'POST',
        url: '/v1/auth/login',
        payload: { email: 'nobody@example.com', password: 'wrong-password-123' },
      });
      statuses.push(res.statusCode);
    }
    expect(statuses.slice(0, 3)).toEqual([401, 401, 401]);
    expect(statuses.slice(3)).toEqual([429, 429]);
    await limited.close();
  });

  it('rejects an oversized body', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: {
        email: uniqueEmail(),
        password: STRONG_PASSWORD,
        organizationName: 'x'.repeat(50_000),
      },
    });
    expect(res.statusCode).toBe(413);
  });
});

describe('secrets and logs', () => {
  it('never writes passwords, session tokens or API keys to the logs', async () => {
    const logs = captureLogs();
    const logged = await createTestApp(db, {}, { stream: logs.stream, level: 'debug' });

    const email = uniqueEmail('logcheck');
    const password = 'a-very-secret-password-4242';
    const register = await logged.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: { email, password, organizationName: 'Log Check' },
    });
    const cookie = register.cookies.find((c) => c.name === SESSION_COOKIE)!;
    const created = await logged.inject({
      method: 'POST',
      url: '/v1/api-keys',
      headers: { cookie: `${SESSION_COOKIE}=${cookie.value}` },
      payload: { name: 'log key' },
    });
    const key = (created.json() as { key: string }).key;
    await logged.inject({
      method: 'GET',
      url: '/v1/whoami',
      headers: { authorization: `Bearer ${key}` },
    });
    await logged.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email, password: 'wrong-password-9999' },
    });

    const text = logs.text();
    expect(text.length).toBeGreaterThan(0); // the logger really was active
    expect(text).not.toContain(password);
    expect(text).not.toContain('wrong-password-9999');
    expect(text).not.toContain(cookie.value);
    expect(text).not.toContain(key);
    await logged.close();
  });
});
