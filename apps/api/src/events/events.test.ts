import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deliveries, events } from '../db/schema.js';
import {
  captureLogs,
  createTestApp,
  createTestDb,
  registerUser,
  type TestApp,
  type TestDb,
} from '../test/helpers.js';

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

/** A user with an organization and an API key. */
async function setup(appUnderTest: TestApp = app, organizationName = 'Acme') {
  const user = await registerUser(appUnderTest, { organizationName });
  const keyRes = await appUnderTest.inject({
    method: 'POST',
    url: '/v1/api-keys',
    headers: { cookie: user.cookieHeader },
    payload: { name: 'test key' },
  });
  const apiKey = (keyRes.json() as { key: string }).key;
  return { ...user, apiKey };
}
type Account = Awaited<ReturnType<typeof setup>>;

async function addEndpoint(
  account: Account,
  name: string,
  eventTypes: string[],
  options: { active?: boolean } = {},
) {
  const res = await app.inject({
    method: 'POST',
    url: '/v1/endpoints',
    headers: { cookie: account.cookieHeader },
    payload: { name, url: `https://hooks.example.com/${name}`, eventTypes },
  });
  const id = (res.json() as { id: string }).id;
  if (options.active === false) {
    await app.inject({
      method: 'PATCH',
      url: `/v1/endpoints/${id}`,
      headers: { cookie: account.cookieHeader },
      payload: { isActive: false },
    });
  }
  return id;
}

function publish(
  account: Account,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
  appUnderTest: TestApp = app,
) {
  return appUnderTest.inject({
    method: 'POST',
    url: '/v1/events',
    headers: { authorization: `Bearer ${account.apiKey}`, ...headers },
    payload: body,
  });
}

const order = { type: 'order.paid', payload: { orderId: 1042, amount: 42000 } };

describe('publishing an event', () => {
  it('stores the event and answers 202', async () => {
    const account = await setup();
    const res = await publish(account, order);
    expect(res.statusCode).toBe(202);
    const body = res.json();
    expect(body.type).toBe('order.paid');
    expect(body.deliveries).toBe(0); // nobody is subscribed yet

    const [row] = await db.select().from(events).where(eq(events.id, body.id));
    expect(row?.payload).toEqual(order.payload);
    expect(row?.organizationId).toBe(account.body.organization.id);
  });

  it('creates one pending delivery per active, matching destination', async () => {
    const account = await setup();
    const exact = await addEndpoint(account, 'exact', ['order.paid']);
    const prefix = await addEndpoint(account, 'prefix', ['order.*']);
    const everything = await addEndpoint(account, 'everything', ['*']);
    await addEndpoint(account, 'other', ['user.created']);
    await addEndpoint(account, 'disabled', ['order.paid'], { active: false });
    await addEndpoint(account, 'no-subscription', []);

    const res = await publish(account, order);
    expect(res.statusCode).toBe(202);
    expect(res.json().deliveries).toBe(3);

    const rows = await db.select().from(deliveries).where(eq(deliveries.eventId, res.json().id));
    expect(rows.map((r) => r.endpointId).sort()).toEqual([exact, prefix, everything].sort());
    for (const row of rows) {
      expect(row.status).toBe('pending');
      expect(row.attemptCount).toBe(0);
      expect(row.nextAttemptAt).toBeInstanceOf(Date);
      expect(row.organizationId).toBe(account.body.organization.id);
    }
  });

  it('creates a single delivery even if several subscriptions match the same destination', async () => {
    const account = await setup();
    await addEndpoint(account, 'many', ['order.paid', 'order.*', '*']);
    const res = await publish(account, order);
    expect(res.json().deliveries).toBe(1);
  });

  it('only delivers to the destinations of its own organization', async () => {
    const a = await setup(app, 'Org A');
    const b = await setup(app, 'Org B');
    const endpointOfA = await addEndpoint(a, 'a-hook', ['*']);
    await addEndpoint(b, 'b-hook', ['*']);

    const res = await publish(a, order);
    expect(res.json().deliveries).toBe(1);
    const rows = await db.select().from(deliveries).where(eq(deliveries.eventId, res.json().id));
    expect(rows.map((r) => r.endpointId)).toEqual([endpointOfA]);
  });
});

describe('authentication and validation', () => {
  it('requires a valid API key', async () => {
    const account = await setup();
    const none = await app.inject({ method: 'POST', url: '/v1/events', payload: order });
    expect(none.statusCode).toBe(401);
    const wrong = await publish({ ...account, apiKey: 'whk_live_not-a-real-key' }, order);
    expect(wrong.statusCode).toBe(401);
  });

  it('refuses a revoked key', async () => {
    const account = await setup();
    const list = await app.inject({
      method: 'GET',
      url: '/v1/api-keys',
      headers: { cookie: account.cookieHeader },
    });
    const keyId = list.json().keys[0].id;
    await app.inject({
      method: 'DELETE',
      url: `/v1/api-keys/${keyId}`,
      headers: { cookie: account.cookieHeader },
    });
    expect((await publish(account, order)).statusCode).toBe(401);
  });

  it('does not accept a dashboard session in place of an API key', async () => {
    const account = await setup();
    const res = await app.inject({
      method: 'POST',
      url: '/v1/events',
      headers: { cookie: account.cookieHeader },
      payload: order,
    });
    expect(res.statusCode).toBe(401);
  });

  it.each([
    ['no type', { payload: {} }],
    ['an empty type', { type: '', payload: {} }],
    ['an upper-case type', { type: 'Order.Paid', payload: {} }],
    ['a wildcard type', { type: 'order.*', payload: {} }],
    ['no payload', { type: 'order.paid' }],
    ['an array payload', { type: 'order.paid', payload: [1, 2] }],
    ['a text payload', { type: 'order.paid', payload: 'hello' }],
  ])('rejects %s', async (_label, body) => {
    const account = await setup();
    const res = await publish(account, body);
    expect(res.statusCode).toBe(400);
    expect(
      await db.select().from(events).where(eq(events.organizationId, account.body.organization.id)),
    ).toEqual([]);
  });

  it('rejects an oversized event', async () => {
    const account = await setup();
    const res = await publish(account, {
      type: 'order.paid',
      payload: { blob: 'x'.repeat(300 * 1024) },
    });
    expect(res.statusCode).toBe(413);
  });

  it('rate-limits publishers', async () => {
    const limited = await createTestApp(db, {
      limits: {
        login: { max: 1000, timeWindow: '1 minute' },
        register: { max: 1000, timeWindow: '1 minute' },
        events: { max: 3, timeWindow: '1 minute' },
      },
    });
    const account = await setup(limited);
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      statuses.push((await publish(account, order, {}, limited)).statusCode);
    }
    expect(statuses).toEqual([202, 202, 202, 429, 429]);
    await limited.close();
  });
});

describe('idempotency', () => {
  it('returns the original event when the same request is repeated', async () => {
    const account = await setup();
    await addEndpoint(account, 'hook', ['order.paid']);
    const body = { ...order, idempotencyKey: 'order-1042' };

    const first = await publish(account, body);
    const second = await publish(account, body);
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(200);
    expect(second.headers['idempotent-replayed']).toBe('true');
    expect(second.json().id).toBe(first.json().id);
    expect(second.json().deliveries).toBe(1);

    const stored = await db
      .select()
      .from(events)
      .where(eq(events.organizationId, account.body.organization.id));
    expect(stored).toHaveLength(1);
    const created = await db
      .select()
      .from(deliveries)
      .where(eq(deliveries.organizationId, account.body.organization.id));
    expect(created).toHaveLength(1); // no duplicate delivery
  });

  it('is not fooled by a different key order in the payload', async () => {
    const account = await setup();
    const first = await publish(account, {
      type: 'order.paid',
      payload: { a: 1, b: { c: 2, d: 3 } },
      idempotencyKey: 'k1',
    });
    const second = await publish(account, {
      type: 'order.paid',
      payload: { b: { d: 3, c: 2 }, a: 1 },
      idempotencyKey: 'k1',
    });
    expect(second.statusCode).toBe(200);
    expect(second.json().id).toBe(first.json().id);
  });

  it('refuses a key reused with different content', async () => {
    const account = await setup();
    await publish(account, { ...order, idempotencyKey: 'reused' });
    const different = await publish(account, {
      type: 'order.paid',
      payload: { orderId: 9999 },
      idempotencyKey: 'reused',
    });
    expect(different.statusCode).toBe(422);
    expect(different.json().error.code).toBe('idempotency_conflict');
  });

  it('accepts the key in the Idempotency-Key header', async () => {
    const account = await setup();
    const first = await publish(account, order, { 'idempotency-key': 'from-header' });
    const second = await publish(account, order, { 'idempotency-key': 'from-header' });
    expect(second.statusCode).toBe(200);
    expect(second.json().id).toBe(first.json().id);
  });

  it('refuses a header and a body key that disagree', async () => {
    const account = await setup();
    const res = await publish(
      account,
      { ...order, idempotencyKey: 'one' },
      { 'idempotency-key': 'two' },
    );
    expect(res.statusCode).toBe(400);
  });

  it('allows the same key in two organizations', async () => {
    const a = await setup(app, 'Idem A');
    const b = await setup(app, 'Idem B');
    const first = await publish(a, { ...order, idempotencyKey: 'shared' });
    const second = await publish(b, { ...order, idempotencyKey: 'shared' });
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(202);
    expect(second.json().id).not.toBe(first.json().id);
  });

  it('creates exactly one event when the same request arrives many times at once', async () => {
    const account = await setup();
    await addEndpoint(account, 'hook', ['order.paid']);
    const body = { ...order, idempotencyKey: 'parallel' };
    const results = await Promise.all(Array.from({ length: 8 }, () => publish(account, body)));

    expect(results.every((r) => r.statusCode === 202 || r.statusCode === 200)).toBe(true);
    expect(new Set(results.map((r) => r.json().id)).size).toBe(1);
    const stored = await db
      .select()
      .from(events)
      .where(
        and(
          eq(events.organizationId, account.body.organization.id),
          eq(events.idempotencyKey, 'parallel'),
        ),
      );
    expect(stored).toHaveLength(1);
    const created = await db
      .select()
      .from(deliveries)
      .where(eq(deliveries.organizationId, account.body.organization.id));
    expect(created).toHaveLength(1);
  });

  it('treats events without a key as separate events', async () => {
    const account = await setup();
    const first = await publish(account, order);
    const second = await publish(account, order);
    expect(second.json().id).not.toBe(first.json().id);
  });
});

describe('reading events (dashboard)', () => {
  it('requires a session', async () => {
    expect((await app.inject({ method: 'GET', url: '/v1/events' })).statusCode).toBe(401);
  });

  it('lists with pagination, newest first, without duplicates or gaps', async () => {
    const account = await setup();
    await addEndpoint(account, 'hook', ['*']);
    const ids: string[] = [];
    for (let i = 0; i < 7; i++) {
      ids.push((await publish(account, { type: 'order.paid', payload: { n: i } })).json().id);
    }

    const seen: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const res = await app.inject({
        method: 'GET',
        url: `/v1/events?limit=3${cursor ? `&cursor=${cursor}` : ''}`,
        headers: { cookie: account.cookieHeader },
      });
      expect(res.statusCode).toBe(200);
      const page = res.json() as {
        events: { id: string; deliveries: { total: number } }[];
        nextCursor: string | null;
      };
      expect(page.events.length).toBeLessThanOrEqual(3);
      expect(page.events[0]?.deliveries.total).toBe(1);
      seen.push(...page.events.map((e) => e.id));
      cursor = page.nextCursor;
      pages += 1;
    } while (cursor && pages < 10);

    expect(pages).toBe(3);
    expect(seen).toHaveLength(7);
    expect(new Set(seen).size).toBe(7); // no duplicates
    expect([...seen].sort()).toEqual([...ids].sort()); // no gaps
    expect(seen[0]).toBe(ids[6]); // newest first
  });

  it('filters by type and rejects a bad cursor', async () => {
    const account = await setup();
    await publish(account, order);
    await publish(account, { type: 'user.created', payload: {} });
    const filtered = await app.inject({
      method: 'GET',
      url: '/v1/events?type=user.created',
      headers: { cookie: account.cookieHeader },
    });
    expect(filtered.json().events).toHaveLength(1);

    const bad = await app.inject({
      method: 'GET',
      url: '/v1/events?cursor=not-a-cursor',
      headers: { cookie: account.cookieHeader },
    });
    expect(bad.statusCode).toBe(400);
  });

  it('shows one event with its payload and deliveries', async () => {
    const account = await setup();
    const endpointId = await addEndpoint(account, 'hook', ['order.paid']);
    const published = await publish(account, order);

    const res = await app.inject({
      method: 'GET',
      url: `/v1/events/${published.json().id}`,
      headers: { cookie: account.cookieHeader },
    });
    expect(res.statusCode).toBe(200);
    const detail = res.json();
    expect(detail.payload).toEqual(order.payload);
    expect(detail.deliveries).toHaveLength(1);
    expect(detail.deliveries[0]).toMatchObject({
      status: 'pending',
      attemptCount: 0,
      attempts: [],
      endpoint: { id: endpointId, name: 'hook' },
    });
  });

  it("never shows another organization's events", async () => {
    const a = await setup(app, 'Read A');
    const b = await setup(app, 'Read B');
    const published = await publish(a, order);

    const detail = await app.inject({
      method: 'GET',
      url: `/v1/events/${published.json().id}`,
      headers: { cookie: b.cookieHeader },
    });
    expect(detail.statusCode).toBe(404);
    const list = await app.inject({
      method: 'GET',
      url: '/v1/events',
      headers: { cookie: b.cookieHeader },
    });
    expect(list.json().events).toEqual([]);
  });
});

describe('payload privacy', () => {
  it('never writes event payloads or API keys to the logs', async () => {
    const logs = captureLogs();
    const logged = await createTestApp(db, {}, { stream: logs.stream, level: 'debug' });
    const account = await setup(logged, 'Log Org');
    const res = await publish(
      account,
      { type: 'order.paid', payload: { customerEmail: 'private.customer@example.com' } },
      {},
      logged,
    );
    expect(res.statusCode).toBe(202);
    expect(logs.text().length).toBeGreaterThan(0);
    expect(logs.text()).not.toContain('private.customer@example.com');
    expect(logs.text()).not.toContain(account.apiKey);
    await logged.close();
  });
});
