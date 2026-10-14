import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { endpoints, memberships, subscriptions } from '../db/schema.js';
import { decryptSecret } from '../security/crypto.js';
import {
  captureLogs,
  createTestApp,
  createTestDb,
  registerUser,
  TEST_ENCRYPTION_KEY,
  type TestApp,
  type TestDb,
} from '../test/helpers.js';
import { MAX_ENDPOINTS_PER_ORG } from './routes.js';

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

async function create(cookieHeader: string, payload: Record<string, unknown> = {}) {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/endpoints',
    headers: { cookie: cookieHeader },
    payload: { name: 'Stock service', url: 'https://hooks.example.com/stock', ...payload },
  });
  return { res, body: res.json() as Record<string, any> }; // eslint-disable-line @typescript-eslint/no-explicit-any
}

describe('creating a destination', () => {
  it('creates it with subscriptions and returns the signing secret once', async () => {
    const { cookieHeader } = await registerUser(app);
    const { res, body } = await create(cookieHeader, {
      eventTypes: ['order.paid', 'invoice.*', 'order.paid'],
    });
    expect(res.statusCode).toBe(201);
    expect(body.signingSecret).toMatch(/^whsec_/);
    expect(body.eventTypes.sort()).toEqual(['invoice.*', 'order.paid']); // duplicate removed
    expect(body.isActive).toBe(true);

    const get = await app.inject({
      method: 'GET',
      url: `/v1/endpoints/${body.id}`,
      headers: { cookie: cookieHeader },
    });
    expect(get.statusCode).toBe(200);
    expect(get.body).not.toContain(body.signingSecret);
    expect(get.body).not.toContain('signingSecret');
  });

  it('stores the secret encrypted, and it decrypts to what was returned', async () => {
    const { cookieHeader } = await registerUser(app);
    const { body } = await create(cookieHeader);
    const [row] = await db.select().from(endpoints).where(eq(endpoints.id, body.id));
    expect(row?.signingSecretEncrypted).not.toContain(body.signingSecret);
    expect(row?.signingSecretEncrypted.startsWith('v1:')).toBe(true);
    expect(decryptSecret(row!.signingSecretEncrypted, TEST_ENCRYPTION_KEY, body.id)).toBe(
      body.signingSecret,
    );
  });

  it('gives each destination a different secret', async () => {
    const { cookieHeader } = await registerUser(app);
    const first = await create(cookieHeader);
    const second = await create(cookieHeader);
    expect(first.body.signingSecret).not.toBe(second.body.signingSecret);
  });

  it('requires a session', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/endpoints',
      payload: { name: 'x', url: 'https://hooks.example.com/x' },
    });
    expect(res.statusCode).toBe(401);
  });

  it.each([
    ['a missing name', { name: '' }],
    ['an invalid event type', { eventTypes: ['Order.Paid'] }],
    ['an event type with consecutive dots', { eventTypes: ['order..paid'] }],
    ['too many event types', { eventTypes: Array.from({ length: 51 }, (_, i) => `event.t${i}`) }],
  ])('rejects %s', async (_label, override) => {
    const { cookieHeader } = await registerUser(app);
    const { res } = await create(cookieHeader, override);
    expect(res.statusCode).toBe(400);
  });

  it('accepts the wildcard forms', async () => {
    const { cookieHeader } = await registerUser(app);
    const { res } = await create(cookieHeader, { eventTypes: ['*', 'user.*', 'user.created'] });
    expect(res.statusCode).toBe(201);
  });
});

describe('SSRF protection', () => {
  it.each([
    ['loopback', 'https://127.0.0.1/hook'],
    ['localhost', 'https://localhost/hook'],
    ['cloud metadata', 'https://169.254.169.254/latest/meta-data'],
    ['a private network', 'https://192.168.1.20/hook'],
    ['an IPv6 loopback', 'https://[::1]/hook'],
    ['an IPv4-mapped IPv6 address', 'https://[::ffff:7f00:1]/hook'],
    ['a decimal IP', 'https://2130706433/hook'],
    ['plain http', 'http://hooks.example.com/hook'],
    ['credentials in the URL', 'https://admin:secret@hooks.example.com/hook'],
    ['a name that resolves to a private address', 'https://internal-db.example.com/hook'],
  ])('refuses %s', async (_label, url) => {
    const { cookieHeader, body: account } = await registerUser(app);
    const { res, body } = await create(cookieHeader, { url });
    expect(res.statusCode).toBe(400);
    expect(body.error.code).toBe('unsafe_url');

    // Nothing was created.
    const rows = await db
      .select()
      .from(endpoints)
      .where(eq(endpoints.organizationId, account.organization.id));
    expect(rows).toEqual([]);
  });

  it('also protects URL changes', async () => {
    const { cookieHeader } = await registerUser(app);
    const { body } = await create(cookieHeader);
    const patch = await app.inject({
      method: 'PATCH',
      url: `/v1/endpoints/${body.id}`,
      headers: { cookie: cookieHeader },
      payload: { url: 'https://169.254.169.254/' },
    });
    expect(patch.statusCode).toBe(400);
    const [row] = await db.select().from(endpoints).where(eq(endpoints.id, body.id));
    expect(row?.url).toBe('https://hooks.example.com/stock');
  });

  it('allows a local receiver only when development mode is on', async () => {
    const dev = await createTestApp(db, { allowPrivateDestinations: true });
    const user = await registerUser(dev);
    const res = await dev.inject({
      method: 'POST',
      url: '/v1/endpoints',
      headers: { cookie: user.cookieHeader },
      payload: { name: 'Local receiver', url: 'http://127.0.0.1:4000/hook' },
    });
    expect(res.statusCode).toBe(201);
    await dev.close();
  });
});

describe('managing destinations', () => {
  it('lists, updates, deactivates and deletes', async () => {
    const { cookieHeader } = await registerUser(app);
    const { body } = await create(cookieHeader, { eventTypes: ['order.paid'] });

    const list = await app.inject({
      method: 'GET',
      url: '/v1/endpoints',
      headers: { cookie: cookieHeader },
    });
    expect(list.json().endpoints).toHaveLength(1);
    expect(list.body).not.toContain('signingSecret');

    const patch = await app.inject({
      method: 'PATCH',
      url: `/v1/endpoints/${body.id}`,
      headers: { cookie: cookieHeader },
      payload: { name: 'Renamed', isActive: false, description: null },
    });
    expect(patch.statusCode).toBe(200);
    expect(patch.json()).toMatchObject({ name: 'Renamed', isActive: false, description: null });

    const empty = await app.inject({
      method: 'PATCH',
      url: `/v1/endpoints/${body.id}`,
      headers: { cookie: cookieHeader },
      payload: {},
    });
    expect(empty.statusCode).toBe(400);

    const del = await app.inject({
      method: 'DELETE',
      url: `/v1/endpoints/${body.id}`,
      headers: { cookie: cookieHeader },
    });
    expect(del.statusCode).toBe(204);
    const subs = await db.select().from(subscriptions).where(eq(subscriptions.endpointId, body.id));
    expect(subs).toEqual([]); // subscriptions are deleted with the destination
  });

  it('replaces the subscriptions', async () => {
    const { cookieHeader } = await registerUser(app);
    const { body } = await create(cookieHeader, { eventTypes: ['order.paid', 'order.refunded'] });
    const res = await app.inject({
      method: 'PUT',
      url: `/v1/endpoints/${body.id}/subscriptions`,
      headers: { cookie: cookieHeader },
      payload: { eventTypes: ['user.created'] },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().eventTypes).toEqual(['user.created']);
    const rows = await db.select().from(subscriptions).where(eq(subscriptions.endpointId, body.id));
    expect(rows.map((r) => r.eventType)).toEqual(['user.created']);
  });

  it('limits the number of destinations per organization', async () => {
    const { cookieHeader, body: account } = await registerUser(app);
    await db.insert(endpoints).values(
      Array.from({ length: MAX_ENDPOINTS_PER_ORG }, (_, i) => ({
        organizationId: account.organization.id,
        name: `bulk ${i}`,
        url: 'https://hooks.example.com/bulk',
        signingSecretEncrypted: 'v1:placeholder',
      })),
    );
    const { res } = await create(cookieHeader);
    expect(res.statusCode).toBe(409);
  });
});

describe('tenant isolation and roles', () => {
  it("never exposes or changes another organization's destinations", async () => {
    const a = await registerUser(app, { organizationName: 'Org A' });
    const b = await registerUser(app, { organizationName: 'Org B' });
    const { body } = await create(a.cookieHeader, { eventTypes: ['order.paid'] });
    const url = `/v1/endpoints/${body.id}`;

    const listOfB = await app.inject({
      method: 'GET',
      url: '/v1/endpoints',
      headers: { cookie: b.cookieHeader },
    });
    expect(listOfB.json().endpoints).toEqual([]);

    for (const attempt of [
      { method: 'GET', url },
      { method: 'PATCH', url, payload: { name: 'hijacked' } },
      { method: 'DELETE', url },
      { method: 'PUT', url: `${url}/subscriptions`, payload: { eventTypes: ['*'] } },
    ] as const) {
      const res = await app.inject({ ...attempt, headers: { cookie: b.cookieHeader } });
      expect(res.statusCode, `${attempt.method} ${attempt.url}`).toBe(404);
    }

    // Nothing changed for A.
    const [row] = await db.select().from(endpoints).where(eq(endpoints.id, body.id));
    expect(row?.name).toBe('Stock service');
    const subs = await db.select().from(subscriptions).where(eq(subscriptions.endpointId, body.id));
    expect(subs.map((s) => s.eventType)).toEqual(['order.paid']);
  });

  it('lets a viewer read but not change', async () => {
    const owner = await registerUser(app);
    const { body } = await create(owner.cookieHeader);
    const viewer = await registerUser(app);
    await db.delete(memberships).where(eq(memberships.userId, viewer.body.user.id));
    await db.insert(memberships).values({
      userId: viewer.body.user.id,
      organizationId: owner.body.organization.id,
      role: 'viewer',
    });

    const read = await app.inject({
      method: 'GET',
      url: '/v1/endpoints',
      headers: { cookie: viewer.cookieHeader },
    });
    expect(read.statusCode).toBe(200);
    expect(read.json().endpoints).toHaveLength(1);

    const write = await create(viewer.cookieHeader);
    expect(write.res.statusCode).toBe(403);
    const del = await app.inject({
      method: 'DELETE',
      url: `/v1/endpoints/${body.id}`,
      headers: { cookie: viewer.cookieHeader },
    });
    expect(del.statusCode).toBe(403);
  });
});

describe('secrets and logs', () => {
  it('never writes a signing secret to the logs', async () => {
    const logs = captureLogs();
    const logged = await createTestApp(db, {}, { stream: logs.stream, level: 'debug' });
    const user = await registerUser(logged);
    const res = await logged.inject({
      method: 'POST',
      url: '/v1/endpoints',
      headers: { cookie: user.cookieHeader },
      payload: { name: 'Logged', url: 'https://hooks.example.com/logged' },
    });
    const secret = (res.json() as { signingSecret: string }).signingSecret;
    await logged.inject({
      method: 'GET',
      url: '/v1/endpoints',
      headers: { cookie: user.cookieHeader },
    });
    expect(logs.text().length).toBeGreaterThan(0);
    expect(logs.text()).not.toContain(secret);
    await logged.close();
  });
});
