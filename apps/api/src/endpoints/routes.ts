import { randomUUID } from 'node:crypto';
import { and, asc, count, eq, inArray } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { SessionContext } from '../auth/context.js';
import type { Db } from '../db/client.js';
import { endpoints, subscriptions } from '../db/schema.js';
import { error, invalid } from '../http/responses.js';
import { encryptSecret } from '../security/crypto.js';
import { randomToken } from '../security/tokens.js';
import { assertPublicDestination, UnsafeUrlError, type Resolver } from '../security/url-guard.js';

export const MAX_ENDPOINTS_PER_ORG = 100;
export const MAX_SUBSCRIPTIONS_PER_ENDPOINT = 50;
const BODY_LIMIT = 64 * 1024;

/**
 * An event type is an exact name ("order.paid"), a prefix wildcard ("invoice.*"), or "*" for
 * everything. Lower case only, so that matching is simple and predictable.
 */
const EVENT_TYPE = /^(\*|[a-z0-9][a-z0-9_-]*(\.[a-z0-9_-]+)*(\.\*)?)$/;
const eventTypes = z
  .array(z.string().min(1).max(100).regex(EVENT_TYPE))
  .max(MAX_SUBSCRIPTIONS_PER_ENDPOINT)
  .transform((list) => [...new Set(list)]);

const createBody = z.object({
  name: z.string().trim().min(1).max(80),
  url: z.string().trim().min(1),
  description: z.string().trim().max(500).optional(),
  eventTypes: eventTypes.default([]),
});
const patchBody = z
  .object({
    name: z.string().trim().min(1).max(80),
    url: z.string().trim().min(1),
    description: z.string().trim().max(500).nullable(),
    isActive: z.boolean(),
  })
  .partial()
  .refine((value) => Object.keys(value).length > 0, { message: 'Nothing to update' });
const subscriptionsBody = z.object({ eventTypes });
const idParams = z.object({ id: z.uuid() });

export interface EndpointRoutesDeps {
  db: Db;
  requireSession: (request: FastifyRequest, reply: FastifyReply) => Promise<SessionContext | null>;
  encryptionKey: Buffer;
  allowPrivateDestinations: boolean;
  resolver?: Resolver;
}

type EndpointRow = typeof endpoints.$inferSelect;

function toDto(row: EndpointRow, types: string[]) {
  // The signing secret is deliberately absent: it is only returned once, when it is created.
  return {
    id: row.id,
    name: row.name,
    url: row.url,
    description: row.description,
    isActive: row.isActive,
    eventTypes: types,
    createdAt: row.createdAt,
  };
}

export function registerEndpointRoutes(app: FastifyInstance, deps: EndpointRoutesDeps) {
  const { db, requireSession, encryptionKey } = deps;

  async function checkUrl(raw: string, reply: FastifyReply): Promise<string | null> {
    try {
      const { url } = await assertPublicDestination(raw, {
        allowPrivateDestinations: deps.allowPrivateDestinations,
        resolver: deps.resolver,
      });
      return url.toString();
    } catch (err) {
      if (err instanceof UnsafeUrlError) {
        await reply.code(400).send(error('unsafe_url', err.message));
        return null;
      }
      throw err;
    }
  }

  async function typesOf(endpointIds: string[]): Promise<Map<string, string[]>> {
    const map = new Map<string, string[]>();
    if (endpointIds.length === 0) return map;
    const rows = await db
      .select({ endpointId: subscriptions.endpointId, eventType: subscriptions.eventType })
      .from(subscriptions)
      .where(inArray(subscriptions.endpointId, endpointIds))
      .orderBy(asc(subscriptions.eventType));
    for (const row of rows) {
      map.set(row.endpointId, [...(map.get(row.endpointId) ?? []), row.eventType]);
    }
    return map;
  }

  function forbidViewer(ctx: SessionContext, reply: FastifyReply): boolean {
    if (ctx.role !== 'viewer') return false;
    void reply.code(403).send(error('forbidden', 'Your role cannot change destinations'));
    return true;
  }

  async function findOwned(id: string, organizationId: string) {
    const [row] = await db
      .select()
      .from(endpoints)
      .where(and(eq(endpoints.id, id), eq(endpoints.organizationId, organizationId)))
      .limit(1);
    return row;
  }

  /* ---------------- create ---------------- */

  app.post('/v1/endpoints', { bodyLimit: BODY_LIMIT }, async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx || forbidViewer(ctx, reply)) return;
    const parsed = createBody.safeParse(request.body);
    if (!parsed.success) return invalid(reply, parsed.error.issues);

    const url = await checkUrl(parsed.data.url, reply);
    if (url === null) return;

    const [{ total } = { total: 0 }] = await db
      .select({ total: count() })
      .from(endpoints)
      .where(eq(endpoints.organizationId, ctx.organizationId));
    if (total >= MAX_ENDPOINTS_PER_ORG) {
      return reply
        .code(409)
        .send(
          error('limit_reached', `An organization can have ${MAX_ENDPOINTS_PER_ORG} endpoints`),
        );
    }

    const id = randomUUID();
    const signingSecret = `whsec_${randomToken(32)}`;
    const row = await db.transaction(async (tx) => {
      const [created] = await tx
        .insert(endpoints)
        .values({
          id,
          organizationId: ctx.organizationId,
          name: parsed.data.name,
          url,
          description: parsed.data.description ?? null,
          // Encrypted, and bound to this endpoint id so it cannot be moved to another row.
          signingSecretEncrypted: encryptSecret(signingSecret, encryptionKey, id),
        })
        .returning();
      if (parsed.data.eventTypes.length > 0) {
        await tx
          .insert(subscriptions)
          .values(parsed.data.eventTypes.map((eventType) => ({ endpointId: id, eventType })));
      }
      return created!;
    });

    // The only time the signing secret is returned.
    return reply.code(201).send({ ...toDto(row, parsed.data.eventTypes), signingSecret });
  });

  /* ---------------- read ---------------- */

  app.get('/v1/endpoints', async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx) return;
    const rows = await db
      .select()
      .from(endpoints)
      .where(eq(endpoints.organizationId, ctx.organizationId))
      .orderBy(asc(endpoints.createdAt));
    const types = await typesOf(rows.map((r) => r.id));
    return { endpoints: rows.map((r) => toDto(r, types.get(r.id) ?? [])) };
  });

  app.get('/v1/endpoints/:id', async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx) return;
    const params = idParams.safeParse(request.params);
    if (!params.success) return invalid(reply, params.error.issues);
    const row = await findOwned(params.data.id, ctx.organizationId);
    if (!row) return reply.code(404).send(error('not_found', 'Endpoint not found'));
    const types = await typesOf([row.id]);
    return toDto(row, types.get(row.id) ?? []);
  });

  /* ---------------- update ---------------- */

  app.patch('/v1/endpoints/:id', { bodyLimit: BODY_LIMIT }, async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx || forbidViewer(ctx, reply)) return;
    const params = idParams.safeParse(request.params);
    if (!params.success) return invalid(reply, params.error.issues);
    const parsed = patchBody.safeParse(request.body);
    if (!parsed.success) return invalid(reply, parsed.error.issues);

    const changes: Partial<typeof endpoints.$inferInsert> = {};
    if (parsed.data.name !== undefined) changes.name = parsed.data.name;
    if (parsed.data.description !== undefined) changes.description = parsed.data.description;
    if (parsed.data.isActive !== undefined) changes.isActive = parsed.data.isActive;
    if (parsed.data.url !== undefined) {
      const url = await checkUrl(parsed.data.url, reply);
      if (url === null) return;
      changes.url = url;
    }

    const [row] = await db
      .update(endpoints)
      .set(changes)
      .where(
        and(eq(endpoints.id, params.data.id), eq(endpoints.organizationId, ctx.organizationId)),
      )
      .returning();
    if (!row) return reply.code(404).send(error('not_found', 'Endpoint not found'));
    const types = await typesOf([row.id]);
    return toDto(row, types.get(row.id) ?? []);
  });

  app.put('/v1/endpoints/:id/subscriptions', { bodyLimit: BODY_LIMIT }, async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx || forbidViewer(ctx, reply)) return;
    const params = idParams.safeParse(request.params);
    if (!params.success) return invalid(reply, params.error.issues);
    const parsed = subscriptionsBody.safeParse(request.body);
    if (!parsed.success) return invalid(reply, parsed.error.issues);

    const row = await findOwned(params.data.id, ctx.organizationId);
    if (!row) return reply.code(404).send(error('not_found', 'Endpoint not found'));

    // Replaces the whole list in one transaction.
    await db.transaction(async (tx) => {
      await tx.delete(subscriptions).where(eq(subscriptions.endpointId, row.id));
      if (parsed.data.eventTypes.length > 0) {
        await tx
          .insert(subscriptions)
          .values(parsed.data.eventTypes.map((eventType) => ({ endpointId: row.id, eventType })));
      }
    });
    return { eventTypes: [...parsed.data.eventTypes].sort() };
  });

  /* ---------------- delete ---------------- */

  app.delete('/v1/endpoints/:id', async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx || forbidViewer(ctx, reply)) return;
    const params = idParams.safeParse(request.params);
    if (!params.success) return invalid(reply, params.error.issues);
    const deleted = await db
      .delete(endpoints)
      .where(
        and(eq(endpoints.id, params.data.id), eq(endpoints.organizationId, ctx.organizationId)),
      )
      .returning({ id: endpoints.id });
    return deleted.length > 0
      ? reply.code(204).send()
      : reply.code(404).send(error('not_found', 'Endpoint not found'));
  });
}
