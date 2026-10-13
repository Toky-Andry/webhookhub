import { PGlite } from '@electric-sql/pglite';
import { DELIVERY_STATUSES } from '@webhookhub/shared';
import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/pglite';
import { migrate } from 'drizzle-orm/pglite/migrator';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as s from './schema.js';

let client: PGlite;
let db: ReturnType<typeof drizzle<typeof s>>;

beforeAll(async () => {
  client = new PGlite(); // in-memory PostgreSQL, no Docker needed
  db = drizzle(client, { schema: s });
  await migrate(db, { migrationsFolder: './drizzle' });
}, 60_000);

afterAll(async () => {
  await client.close();
});

/** Collects the message of an error and of its causes, to look for a constraint name. */
async function failureOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    let text = '';
    let current: unknown = error;
    while (current instanceof Error) {
      text += ` ${current.message}`;
      current = current.cause;
    }
    return text;
  }
  throw new Error('Expected the query to fail, but it succeeded');
}

async function createOrg(name: string) {
  const [org] = await db.insert(s.organizations).values({ name }).returning();
  return org!;
}

async function createEndpoint(organizationId: string, url = 'https://example.com/hook') {
  const [endpoint] = await db
    .insert(s.endpoints)
    .values({ organizationId, name: 'Test', url, signingSecretEncrypted: 'enc:xxx' })
    .returning();
  return endpoint!;
}

async function createEvent(organizationId: string, idempotencyKey?: string) {
  const [event] = await db
    .insert(s.events)
    .values({ organizationId, type: 'order.paid', payload: { amount: 42000 }, idempotencyKey })
    .returning();
  return event!;
}

describe('schema', () => {
  it('keeps delivery statuses in sync with @webhookhub/shared', () => {
    expect([...s.deliveryStatus.enumValues]).toEqual([...DELIVERY_STATUSES]);
  });

  it('stores an event, a delivery and an attempt', async () => {
    const org = await createOrg('Acme');
    const endpoint = await createEndpoint(org.id);
    const event = await createEvent(org.id);
    const [delivery] = await db
      .insert(s.deliveries)
      .values({ eventId: event.id, endpointId: endpoint.id, organizationId: org.id })
      .returning();
    expect(delivery!.status).toBe('pending');
    expect(delivery!.attemptCount).toBe(0);

    await db.insert(s.attempts).values({
      deliveryId: delivery!.id,
      attemptNumber: 1,
      statusCode: 503,
      durationMs: 1200,
    });
    const rows = await db.select().from(s.attempts).where(eq(s.attempts.deliveryId, delivery!.id));
    expect(rows).toHaveLength(1);
  });
});

describe('idempotency', () => {
  it('rejects the same idempotency key twice in one organization', async () => {
    const org = await createOrg('Idem A');
    await createEvent(org.id, 'order-1042');
    expect(await failureOf(createEvent(org.id, 'order-1042'))).toContain(
      'events_org_idempotency_unique',
    );
  });

  it('allows the same key in two different organizations', async () => {
    const a = await createOrg('Idem B1');
    const b = await createOrg('Idem B2');
    await createEvent(a.id, 'shared-key');
    await expect(createEvent(b.id, 'shared-key')).resolves.toBeDefined();
  });

  it('allows several events without a key', async () => {
    const org = await createOrg('Idem C');
    await createEvent(org.id);
    await expect(createEvent(org.id)).resolves.toBeDefined();
  });
});

describe('tenant isolation', () => {
  it('refuses a delivery that mixes an event and an endpoint from two organizations', async () => {
    const a = await createOrg('Tenant A');
    const b = await createOrg('Tenant B');
    const endpointOfB = await createEndpoint(b.id);
    const eventOfA = await createEvent(a.id);

    // Claiming organization A: the endpoint does not belong to A.
    const message = await failureOf(
      db
        .insert(s.deliveries)
        .values({ eventId: eventOfA.id, endpointId: endpointOfB.id, organizationId: a.id }),
    );
    expect(message).toContain('deliveries_endpoint_org_fk');
  });

  it('refuses a delivery whose organization differs from the event organization', async () => {
    const a = await createOrg('Tenant C');
    const b = await createOrg('Tenant D');
    const endpointOfB = await createEndpoint(b.id);
    const eventOfA = await createEvent(a.id);

    const message = await failureOf(
      db
        .insert(s.deliveries)
        .values({ eventId: eventOfA.id, endpointId: endpointOfB.id, organizationId: b.id }),
    );
    expect(message).toContain('deliveries_event_org_fk');
  });
});

describe('delivery rules', () => {
  it('allows only one delivery per event and endpoint', async () => {
    const org = await createOrg('Dup');
    const endpoint = await createEndpoint(org.id);
    const event = await createEvent(org.id);
    const values = { eventId: event.id, endpointId: endpoint.id, organizationId: org.id };
    await db.insert(s.deliveries).values(values);
    expect(await failureOf(db.insert(s.deliveries).values(values))).toContain(
      'deliveries_event_endpoint_unique',
    );
  });

  it('rejects an attempt count above 8', async () => {
    const org = await createOrg('Max');
    const endpoint = await createEndpoint(org.id);
    const event = await createEvent(org.id);
    const message = await failureOf(
      db.insert(s.deliveries).values({
        eventId: event.id,
        endpointId: endpoint.id,
        organizationId: org.id,
        attemptCount: 9,
      }),
    );
    expect(message).toContain('deliveries_attempt_count_range');
  });

  it('rejects an unknown status', async () => {
    const org = await createOrg('Status');
    const endpoint = await createEndpoint(org.id);
    const event = await createEvent(org.id);
    const message = await failureOf(
      db.insert(s.deliveries).values({
        eventId: event.id,
        endpointId: endpoint.id,
        organizationId: org.id,
        status: 'exploded' as never,
      }),
    );
    expect(message).toMatch(/delivery_status|invalid input value/);
  });

  it('rejects two attempts with the same number', async () => {
    const org = await createOrg('Attempts');
    const endpoint = await createEndpoint(org.id);
    const event = await createEvent(org.id);
    const [delivery] = await db
      .insert(s.deliveries)
      .values({ eventId: event.id, endpointId: endpoint.id, organizationId: org.id })
      .returning();
    await db.insert(s.attempts).values({ deliveryId: delivery!.id, attemptNumber: 1 });
    expect(
      await failureOf(db.insert(s.attempts).values({ deliveryId: delivery!.id, attemptNumber: 1 })),
    ).toContain('attempts_delivery_number_unique');
  });
});

describe('uniqueness and cleanup', () => {
  it('rejects a duplicate subscription', async () => {
    const org = await createOrg('Subs');
    const endpoint = await createEndpoint(org.id);
    await db.insert(s.subscriptions).values({ endpointId: endpoint.id, eventType: 'order.paid' });
    expect(
      await failureOf(
        db.insert(s.subscriptions).values({ endpointId: endpoint.id, eventType: 'order.paid' }),
      ),
    ).toContain('subscriptions_endpoint_event_unique');
  });

  it('rejects a duplicate API key hash', async () => {
    const org = await createOrg('Keys');
    const key = { organizationId: org.id, name: 'k', keyPrefix: 'whk_live_a1b2', keyHash: 'h1' };
    await db.insert(s.apiKeys).values(key);
    expect(await failureOf(db.insert(s.apiKeys).values(key))).toContain('api_keys_key_hash_unique');
  });

  it('deletes everything that belongs to an organization when it is deleted', async () => {
    const org = await createOrg('To delete');
    const endpoint = await createEndpoint(org.id);
    const event = await createEvent(org.id);
    const [delivery] = await db
      .insert(s.deliveries)
      .values({ eventId: event.id, endpointId: endpoint.id, organizationId: org.id })
      .returning();
    await db.insert(s.attempts).values({ deliveryId: delivery!.id, attemptNumber: 1 });

    await db.delete(s.organizations).where(eq(s.organizations.id, org.id));

    expect(await db.select().from(s.events).where(eq(s.events.organizationId, org.id))).toEqual([]);
    expect(
      await db.select().from(s.attempts).where(eq(s.attempts.deliveryId, delivery!.id)),
    ).toEqual([]);
  });
});
