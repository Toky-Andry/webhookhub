import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import { and, asc, eq, isNull } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Db } from '../db/client.js';
import { apiKeys, memberships, organizations, sessions, users } from '../db/schema.js';
import { hashPassword, verifyAgainstDummy, verifyPassword } from '../security/password.js';
import { generateApiKey, randomToken, sha256Hex } from '../security/tokens.js';
import {
  apiKeyContextFromHeader,
  sessionContextFromToken,
  type SessionContext,
} from './context.js';

export const SESSION_COOKIE = 'wh_session';

export interface AuthPluginOptions {
  db: Db;
  sessionTtlHours: number;
  /** Set to true in production (HTTPS only). */
  secureCookies: boolean;
  limits?: {
    login: { max: number; timeWindow: string };
    register: { max: number; timeWindow: string };
  };
}

const AUTH_BODY_LIMIT = 10 * 1024; // 10 KB is plenty for these small JSON bodies

const registerBody = z.object({
  email: z
    .email()
    .max(254)
    .transform((v) => v.trim().toLowerCase()),
  // 12+ characters (length matters most), capped to avoid very long inputs slowing down hashing.
  password: z.string().min(12).max(128),
  organizationName: z.string().trim().min(2).max(80),
});
const loginBody = z.object({
  email: z
    .string()
    .max(254)
    .transform((v) => v.trim().toLowerCase()),
  password: z.string().min(1).max(128),
});
const createKeyBody = z.object({ name: z.string().trim().min(1).max(80) });
const idParams = z.object({ id: z.uuid() });

function error(code: string, message: string) {
  return { error: { code, message } };
}

function invalid(reply: FastifyReply, issues: z.core.$ZodIssue[]) {
  // Only field names are returned, never the submitted values (they may contain a password).
  const fields = [...new Set(issues.map((i) => i.path.join('.') || '(body)'))];
  return reply
    .code(400)
    .send({ error: { code: 'invalid_request', message: 'Invalid request', fields } });
}

function isUniqueViolation(err: unknown): boolean {
  let current: unknown = err;
  while (current && typeof current === 'object') {
    if ((current as { code?: string }).code === '23505') return true;
    current = (current as { cause?: unknown }).cause;
  }
  return false;
}

export async function authPlugin(app: FastifyInstance, options: AuthPluginOptions) {
  const { db, sessionTtlHours, secureCookies } = options;
  const limits = options.limits ?? {
    login: { max: 10, timeWindow: '1 minute' },
    register: { max: 5, timeWindow: '1 hour' },
  };

  await app.register(cookie);
  await app.register(rateLimit, { global: false });

  /* ---------------- helpers ---------------- */

  async function startSession(reply: FastifyReply, userId: string) {
    const token = randomToken(32);
    const expiresAt = new Date(Date.now() + sessionTtlHours * 3_600_000);
    await db.insert(sessions).values({ userId, tokenHash: sha256Hex(token), expiresAt });
    reply.setCookie(SESSION_COOKIE, token, {
      httpOnly: true, // not readable by JavaScript: limits the damage of an XSS
      secure: secureCookies,
      sameSite: 'lax', // not sent on cross-site POST/DELETE: protects against CSRF
      path: '/',
      expires: expiresAt,
    });
  }

  async function requireSession(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<SessionContext | null> {
    const ctx = await sessionContextFromToken(db, request.cookies[SESSION_COOKIE]);
    if (!ctx) {
      await reply.code(401).send(error('unauthorized', 'Authentication required'));
      return null;
    }
    return ctx;
  }

  /* ---------------- authentication ---------------- */

  app.post(
    '/v1/auth/register',
    { bodyLimit: AUTH_BODY_LIMIT, config: { rateLimit: limits.register } },
    async (request, reply) => {
      const parsed = registerBody.safeParse(request.body);
      if (!parsed.success) return invalid(reply, parsed.error.issues);
      const { email, password, organizationName } = parsed.data;

      const [existing] = await db
        .select({ id: users.id })
        .from(users)
        .where(eq(users.email, email));
      if (existing) {
        return reply.code(409).send(error('email_taken', 'This email is already registered'));
      }

      const passwordHash = await hashPassword(password);
      try {
        const created = await db.transaction(async (tx) => {
          const [user] = await tx.insert(users).values({ email, passwordHash }).returning();
          const [org] = await tx
            .insert(organizations)
            .values({ name: organizationName })
            .returning();
          await tx
            .insert(memberships)
            .values({ userId: user!.id, organizationId: org!.id, role: 'owner' });
          return { user: user!, org: org! };
        });
        await startSession(reply, created.user.id);
        return reply.code(201).send({
          user: { id: created.user.id, email: created.user.email },
          organization: { id: created.org.id, name: created.org.name },
        });
      } catch (err) {
        if (isUniqueViolation(err)) {
          return reply.code(409).send(error('email_taken', 'This email is already registered'));
        }
        throw err;
      }
    },
  );

  app.post(
    '/v1/auth/login',
    { bodyLimit: AUTH_BODY_LIMIT, config: { rateLimit: limits.login } },
    async (request, reply) => {
      const parsed = loginBody.safeParse(request.body);
      if (!parsed.success) return invalid(reply, parsed.error.issues);
      const { email, password } = parsed.data;

      const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);
      const ok = user ? await verifyPassword(user.passwordHash, password) : false;
      if (!user) await verifyAgainstDummy(password);

      // Same answer for "unknown email" and "wrong password".
      if (!user || !ok) {
        return reply.code(401).send(error('invalid_credentials', 'Invalid email or password'));
      }

      await startSession(reply, user.id);
      return { user: { id: user.id, email: user.email } };
    },
  );

  app.post('/v1/auth/logout', async (request, reply) => {
    const token = request.cookies[SESSION_COOKIE];
    if (token) await db.delete(sessions).where(eq(sessions.tokenHash, sha256Hex(token)));
    reply.clearCookie(SESSION_COOKIE, { path: '/' });
    return reply.code(204).send();
  });

  app.get('/v1/auth/me', async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx) return;
    return {
      user: { id: ctx.userId, email: ctx.email },
      organization: { id: ctx.organizationId, name: ctx.organizationName },
      role: ctx.role,
    };
  });

  /* ---------------- API keys (managed from the dashboard, with a session) ---------------- */

  app.post('/v1/api-keys', { bodyLimit: AUTH_BODY_LIMIT }, async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx) return;
    if (ctx.role === 'viewer') {
      return reply.code(403).send(error('forbidden', 'Your role cannot create API keys'));
    }
    const parsed = createKeyBody.safeParse(request.body);
    if (!parsed.success) return invalid(reply, parsed.error.issues);

    const generated = generateApiKey();
    const [row] = await db
      .insert(apiKeys)
      .values({
        organizationId: ctx.organizationId,
        name: parsed.data.name,
        keyPrefix: generated.prefix,
        keyHash: generated.hash,
      })
      .returning();

    // The only time the full key is returned. It cannot be recovered later.
    return reply.code(201).send({
      id: row!.id,
      name: row!.name,
      prefix: row!.keyPrefix,
      key: generated.key,
      createdAt: row!.createdAt,
    });
  });

  app.get('/v1/api-keys', async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx) return;
    const rows = await db
      .select({
        id: apiKeys.id,
        name: apiKeys.name,
        prefix: apiKeys.keyPrefix,
        createdAt: apiKeys.createdAt,
        lastUsedAt: apiKeys.lastUsedAt,
        revokedAt: apiKeys.revokedAt,
      })
      .from(apiKeys)
      .where(eq(apiKeys.organizationId, ctx.organizationId))
      .orderBy(asc(apiKeys.createdAt));
    return { keys: rows };
  });

  app.delete('/v1/api-keys/:id', async (request, reply) => {
    const ctx = await requireSession(request, reply);
    if (!ctx) return;
    if (ctx.role === 'viewer') {
      return reply.code(403).send(error('forbidden', 'Your role cannot revoke API keys'));
    }
    const params = idParams.safeParse(request.params);
    if (!params.success) return invalid(reply, params.error.issues);

    // The organization filter is what stops one tenant from revoking another tenant's key.
    const revoked = await db
      .update(apiKeys)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(apiKeys.id, params.data.id),
          eq(apiKeys.organizationId, ctx.organizationId),
          isNull(apiKeys.revokedAt),
        ),
      )
      .returning({ id: apiKeys.id });
    if (revoked.length > 0) return reply.code(204).send();

    // Already revoked (idempotent) or not found / not ours (same answer: 404).
    const [owned] = await db
      .select({ id: apiKeys.id })
      .from(apiKeys)
      .where(and(eq(apiKeys.id, params.data.id), eq(apiKeys.organizationId, ctx.organizationId)));
    return owned
      ? reply.code(204).send()
      : reply.code(404).send(error('not_found', 'API key not found'));
  });

  /* ---------------- API key authentication (used by applications) ---------------- */

  // Lets an application check that its key works. Event publishing will use the same check.
  app.get('/v1/whoami', async (request, reply) => {
    const ctx = await apiKeyContextFromHeader(db, request.headers.authorization);
    if (!ctx) return reply.code(401).send(error('unauthorized', 'Invalid or revoked API key'));
    return { organizationId: ctx.organizationId, keyId: ctx.keyId };
  });
}
