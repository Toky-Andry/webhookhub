import { and, asc, desc, eq, inArray, sql } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { apiKeyContextFromHeader, type SessionContext } from '../auth/context.js';
import type { Db } from '../db/client.js';
import { isUniqueViolation } from '../db/errors.js';
import { attempts, deliveries, endpoints, events, subscriptions } from '../db/schema.js';
import { error, invalid } from '../http/responses.js';
import { sha256Hex } from '../security/tokens.js';
import { matchesSubscription, stableStringify } from './matching.js';

export const MAX_EVENT_BYTES = 256 * 1024;

/** Exact event names only: wildcards belong to subscriptions, not to published events. */
const EVENT_TYPE = /^[a-z0-9][a-z0-9_-]*(\.[a-z0-9_-]+)*$/;
const idempotencyKey = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[\x21-\x7e]+$/, 'printable characters without spaces only');

const publishBody = z.object({
  type: z.string().min(1).max(100).regex(EVENT_TYPE),
  // Any JSON object. Arrays and bare values are refused so that the payload can evolve.
  payload: z.record(z.string(), z.unknown()),
  idempotencyKey: idempotencyKey.optional(),
});
const listQuery = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: z.string().max(200).optional(),
  type: z.string().max(100).optional(),
});
const idParams = z.object({ id: z.uuid() });

export interface EventRoutesDeps {
  db: Db;
  requireSession: (request: FastifyRequest, reply: FastifyReply) => Promise<SessionContext | null>;
  rateLimit: { max: number; timeWindow: string };
}

/** Keyset pagination cursor: creation time (microsecond precision) and id. */
function encodeCursor(createdAt: string, id: string): string {
  return Buffer.from(`${createdAt}|${id}`).toString('base64url');
}
function decodeCursor(cursor: string): { createdAt: string; id: string } | null {
  const [createdAt, id] = Buffer.from(cursor, 'base64url').toString().split('|');
  if (!createdAt || !id || !z.iso.datetime({ precision: 6 }).safeParse(createdAt).success) {
    return null;
  }
  return z.uuid().safeParse(id).success ? { createdAt, id } : null;
}

export function registerEventRoutes(app: FastifyInstance, deps: EventRoutesDeps) {
  const { db, requireSession } = deps;

  /* ---------------- publish (used by applications, with an API key) ---------------- */

  app.post(
    '/v1/events',
    { bodyLimit: MAX_EVENT_BYTES, config: { rateLimit: deps.rateLimit } },
    async (request, reply) => {
      const ctx = await apiKeyContextFromHeader(db, request.headers.authorization);
      if (!ctx) return reply.code(401).send(error('unauthorized', 'Invalid or revoked API key'));

      const parsed = publishBody.safeParse(request.body);
      if (!parsed.success) return invalid(reply, parsed.error.issues);
      const { type, payload } = parsed.data;

      // The idempotency key can come from the body or from the "Idempotency-Key" header.
      const header = request.headers['idempotency-key'];
      let key = parsed.data.idempotencyKey;
      if (header !== undefined) {
        const fromHeader = idempotencyKey.safeParse(header);
        if (!fromHeader.success) return invalid(reply, fromHeader.error.issues);
        if (key !== undefined && key !== fromHeader.data) {
          return reply
            .code(400)
            .send(error('idempotency_mismatch', 'The header and the body use different keys'));
        }
        key = fromHeader.data;
      }
      const requestHash = key ? sha256Hex(stableStringify({ type, payload })) : null;

      // Sends the answer for an already known key and returns true; returns false if the key is new.
      // It returns a boolean on purpose: a Fastify reply is "thenable", so awaiting a function that
      // returns the reply would hide it (the caller would receive undefined and keep going).
      const replay = async (): Promise<boolean> => {
        const [existing] = await db
          .select()
          .from(events)
          .where(
            and(eq(events.organizationId, ctx.organizationId), eq(events.idempotencyKey, key!)),
          )
          .limit(1);
        if (!existing) return false;
        if (existing.requestHash !== requestHash) {
          void reply
            .code(422)
            .send(
              error(
                'idempotency_conflict',
                'This idempotency key was already used with a different event',
              ),
            );
          return true;
        }
        const rows = await db
          .select({ id: deliveries.id })
          .from(deliveries)
          .where(eq(deliveries.eventId, existing.id));
        void reply.code(200).header('Idempotent-Replayed', 'true').send({
          id: existing.id,
          type: existing.type,
          createdAt: existing.createdAt,
          deliveries: rows.length,
        });
        return true;
      };

      if (key && (await replay())) return reply;

      try {
        // The event and all its deliveries are written together, or not at all.
        const created = await db.transaction(async (tx) => {
          const [event] = await tx
            .insert(events)
            .values({
              organizationId: ctx.organizationId,
              type,
              payload,
              idempotencyKey: key ?? null,
              requestHash,
            })
            .returning();

          const candidates = await tx
            .select({ endpointId: endpoints.id, pattern: subscriptions.eventType })
            .from(endpoints)
            .innerJoin(subscriptions, eq(subscriptions.endpointId, endpoints.id))
            .where(
              and(eq(endpoints.organizationId, ctx.organizationId), eq(endpoints.isActive, true)),
            );
          const targets = [
            ...new Set(
              candidates
                .filter((c) => matchesSubscription(c.pattern, type))
                .map((c) => c.endpointId),
            ),
          ];

          if (targets.length > 0) {
            const now = new Date();
            await tx.insert(deliveries).values(
              targets.map((endpointId) => ({
                eventId: event!.id,
                endpointId,
                organizationId: ctx.organizationId,
                status: 'pending' as const,
                nextAttemptAt: now,
              })),
            );
          }
          return { event: event!, deliveries: targets.length };
        });

        // 202: the event is safely stored, delivery happens afterwards.
        return reply.code(202).send({
          id: created.event.id,
          type: created.event.type,
          createdAt: created.event.createdAt,
          deliveries: created.deliveries,
        });
      } catch (err) {
        // Two requests with the same key at the same time: the database let only one win.
        if (key && isUniqueViolation(err) && (await replay())) return reply;
        throw err;
      }
    },
  );

  /* ---------------- read (used by the dashboard, with a session) ---------------- */

  app.get('/v1/events', async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx) return;
    const query = listQuery.safeParse(request.query);
    if (!query.success) return invalid(reply, query.error.issues);

    const conditions = [eq(events.organizationId, ctx.organizationId)];
    if (query.data.type) conditions.push(eq(events.type, query.data.type));
    if (query.data.cursor) {
      const cursor = decodeCursor(query.data.cursor);
      if (!cursor) return reply.code(400).send(error('invalid_cursor', 'Invalid cursor'));
      conditions.push(
        sql`(${events.createdAt}, ${events.id}) < (${cursor.createdAt}::timestamptz, ${cursor.id}::uuid)`,
      );
    }

    const rows = await db
      .select({
        id: events.id,
        type: events.type,
        createdAt: events.createdAt,
        // Full precision, as text: a JavaScript Date would lose microseconds.
        cursorTime: sql<string>`to_char(${events.createdAt} at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`,
      })
      .from(events)
      .where(and(...conditions))
      .orderBy(desc(events.createdAt), desc(events.id))
      .limit(query.data.limit + 1);

    const page = rows.slice(0, query.data.limit);
    const last = page[page.length - 1];
    const nextCursor =
      rows.length > page.length && last ? encodeCursor(last.cursorTime, last.id) : null;

    const counts = new Map<string, Record<string, number>>();
    if (page.length > 0) {
      const grouped = await db
        .select({
          eventId: deliveries.eventId,
          status: deliveries.status,
          total: sql<number>`count(*)::int`,
        })
        .from(deliveries)
        .where(
          inArray(
            deliveries.eventId,
            page.map((e) => e.id),
          ),
        )
        .groupBy(deliveries.eventId, deliveries.status);
      for (const g of grouped) {
        counts.set(g.eventId, { ...counts.get(g.eventId), [g.status]: g.total });
      }
    }

    return {
      events: page.map((e) => {
        const byStatus = counts.get(e.id) ?? {};
        return {
          id: e.id,
          type: e.type,
          createdAt: e.createdAt,
          deliveries: {
            total: Object.values(byStatus).reduce((a, b) => a + b, 0),
            byStatus,
          },
        };
      }),
      nextCursor,
    };
  });

  app.get('/v1/events/:id', async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx) return;
    const params = idParams.safeParse(request.params);
    if (!params.success) return invalid(reply, params.error.issues);

    const [event] = await db
      .select()
      .from(events)
      .where(and(eq(events.id, params.data.id), eq(events.organizationId, ctx.organizationId)))
      .limit(1);
    if (!event) return reply.code(404).send(error('not_found', 'Event not found'));

    const deliveryRows = await db
      .select({
        id: deliveries.id,
        status: deliveries.status,
        attemptCount: deliveries.attemptCount,
        nextAttemptAt: deliveries.nextAttemptAt,
        endpointId: endpoints.id,
        endpointName: endpoints.name,
        endpointUrl: endpoints.url,
      })
      .from(deliveries)
      .innerJoin(endpoints, eq(endpoints.id, deliveries.endpointId))
      .where(eq(deliveries.eventId, event.id))
      .orderBy(asc(endpoints.name));

    const attemptRows =
      deliveryRows.length === 0
        ? []
        : await db
            .select()
            .from(attempts)
            .where(
              inArray(
                attempts.deliveryId,
                deliveryRows.map((d) => d.id),
              ),
            )
            .orderBy(asc(attempts.attemptNumber));

    return {
      id: event.id,
      type: event.type,
      payload: event.payload,
      idempotencyKey: event.idempotencyKey,
      createdAt: event.createdAt,
      deliveries: deliveryRows.map((d) => ({
        id: d.id,
        status: d.status,
        attemptCount: d.attemptCount,
        nextAttemptAt: d.nextAttemptAt,
        endpoint: { id: d.endpointId, name: d.endpointName, url: d.endpointUrl },
        attempts: attemptRows
          .filter((a) => a.deliveryId === d.id)
          .map((a) => ({
            number: a.attemptNumber,
            startedAt: a.startedAt,
            durationMs: a.durationMs,
            statusCode: a.statusCode,
            responseExcerpt: a.responseExcerpt,
            error: a.error,
          })),
      })),
    };
  });
}
