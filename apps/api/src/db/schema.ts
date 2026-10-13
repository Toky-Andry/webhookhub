import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  boolean,
} from 'drizzle-orm/pg-core';

const createdAt = () => timestamp('created_at', { withTimezone: true }).notNull().defaultNow();

// Keep this list identical to DELIVERY_STATUSES in @webhookhub/shared (a test checks it).
export const deliveryStatus = pgEnum('delivery_status', [
  'pending',
  'sending',
  'retrying',
  'delivered',
  'dead',
]);

export const memberRole = pgEnum('member_role', ['owner', 'admin', 'developer', 'viewer']);

/* ------------------------------------------------------------------ */
/* Tenants and access                                                  */
/* ------------------------------------------------------------------ */

export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  createdAt: createdAt(),
});

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  // The application must store emails in lower case.
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  createdAt: createdAt(),
});

export const memberships = pgTable(
  'memberships',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    role: memberRole('role').notNull().default('developer'),
    createdAt: createdAt(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.organizationId] })],
);

export const apiKeys = pgTable(
  'api_keys',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    /** First characters of the key (e.g. whk_live_a1b2), safe to display. */
    keyPrefix: text('key_prefix').notNull(),
    /** SHA-256 hash of the full key. The key itself is never stored. */
    keyHash: text('key_hash').notNull().unique(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [index('api_keys_org_idx').on(t.organizationId)],
);

/* ------------------------------------------------------------------ */
/* Destinations and subscriptions                                      */
/* ------------------------------------------------------------------ */

export const endpoints = pgTable(
  'endpoints',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    url: text('url').notNull(),
    description: text('description'),
    /** HMAC signing secret, encrypted at rest (AES-256-GCM). Never store it in clear text. */
    signingSecretEncrypted: text('signing_secret_encrypted').notNull(),
    isActive: boolean('is_active').notNull().default(true),
    createdAt: createdAt(),
  },
  (t) => [
    index('endpoints_org_idx').on(t.organizationId),
    // Lets other tables reference (id, organization_id) so a row can never point to another tenant.
    unique('endpoints_id_org_unique').on(t.id, t.organizationId),
  ],
);

export const subscriptions = pgTable(
  'subscriptions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    endpointId: uuid('endpoint_id')
      .notNull()
      .references(() => endpoints.id, { onDelete: 'cascade' }),
    eventType: text('event_type').notNull(),
  },
  (t) => [unique('subscriptions_endpoint_event_unique').on(t.endpointId, t.eventType)],
);

/* ------------------------------------------------------------------ */
/* Events, deliveries, attempts                                        */
/* ------------------------------------------------------------------ */

export const events = pgTable(
  'events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    type: text('type').notNull(),
    payload: jsonb('payload').notNull(),
    /** Optional. When present, the same key cannot be published twice by the same organization. */
    idempotencyKey: text('idempotency_key'),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex('events_org_idempotency_unique').on(t.organizationId, t.idempotencyKey),
    index('events_org_created_idx').on(t.organizationId, t.createdAt.desc()),
    unique('events_id_org_unique').on(t.id, t.organizationId),
  ],
);

export const deliveries = pgTable(
  'deliveries',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    eventId: uuid('event_id').notNull(),
    endpointId: uuid('endpoint_id').notNull(),
    /** Copied from the event and the endpoint, and enforced by the composite foreign keys below. */
    organizationId: uuid('organization_id').notNull(),
    status: deliveryStatus('status').notNull().default('pending'),
    attemptCount: integer('attempt_count').notNull().default(0),
    nextAttemptAt: timestamp('next_attempt_at', { withTimezone: true }),
    createdAt: createdAt(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    foreignKey({
      name: 'deliveries_event_org_fk',
      columns: [t.eventId, t.organizationId],
      foreignColumns: [events.id, events.organizationId],
    }).onDelete('cascade'),
    foreignKey({
      name: 'deliveries_endpoint_org_fk',
      columns: [t.endpointId, t.organizationId],
      foreignColumns: [endpoints.id, endpoints.organizationId],
    }).onDelete('cascade'),
    // One delivery per event and destination.
    unique('deliveries_event_endpoint_unique').on(t.eventId, t.endpointId),
    check('deliveries_attempt_count_range', sql`${t.attemptCount} >= 0 AND ${t.attemptCount} <= 8`),
    index('deliveries_org_status_idx').on(t.organizationId, t.status),
    // Used by the worker to find what is due.
    index('deliveries_due_idx').on(t.status, t.nextAttemptAt),
  ],
);

export const attempts = pgTable(
  'attempts',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    deliveryId: uuid('delivery_id')
      .notNull()
      .references(() => deliveries.id, { onDelete: 'cascade' }),
    attemptNumber: integer('attempt_number').notNull(),
    startedAt: timestamp('started_at', { withTimezone: true }).notNull().defaultNow(),
    durationMs: integer('duration_ms'),
    statusCode: integer('status_code'),
    /** Truncated response body (a few KB at most). */
    responseExcerpt: text('response_excerpt'),
    error: text('error'),
  },
  (t) => [
    unique('attempts_delivery_number_unique').on(t.deliveryId, t.attemptNumber),
    check('attempts_number_positive', sql`${t.attemptNumber} >= 1`),
  ],
);
