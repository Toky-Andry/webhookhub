import { and, asc, eq, gt, isNull } from 'drizzle-orm';
import type { Db } from '../db/client.js';
import { apiKeys, memberships, organizations, sessions, users } from '../db/schema.js';
import { sha256Hex } from '../security/tokens.js';

export type Role = 'owner' | 'admin' | 'developer' | 'viewer';

export interface SessionContext {
  sessionId: string;
  userId: string;
  email: string;
  organizationId: string;
  organizationName: string;
  role: Role;
}

/** Resolves a session token (from the cookie) to a user and an organization, or null. */
export async function sessionContextFromToken(
  db: Db,
  token: string | undefined,
): Promise<SessionContext | null> {
  if (!token) return null;

  const [row] = await db
    .select({ sessionId: sessions.id, userId: users.id, email: users.email })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(and(eq(sessions.tokenHash, sha256Hex(token)), gt(sessions.expiresAt, new Date())))
    .limit(1);
  if (!row) return null;

  // A user can belong to several organizations. For now the oldest membership is the active one.
  const [membership] = await db
    .select({
      organizationId: organizations.id,
      organizationName: organizations.name,
      role: memberships.role,
    })
    .from(memberships)
    .innerJoin(organizations, eq(organizations.id, memberships.organizationId))
    .where(eq(memberships.userId, row.userId))
    .orderBy(asc(memberships.createdAt))
    .limit(1);
  if (!membership) return null;

  return { ...row, ...membership };
}

export interface ApiKeyContext {
  keyId: string;
  organizationId: string;
}

const LAST_USED_REFRESH_MS = 60_000;

/** Resolves an "Authorization: Bearer whk_live_..." header to an organization, or null. */
export async function apiKeyContextFromHeader(
  db: Db,
  header: string | undefined,
): Promise<ApiKeyContext | null> {
  const match = /^Bearer (\S+)$/.exec(header ?? '');
  if (!match) return null;

  // Keys are 256-bit random values, so a lookup by hash is safe: nothing useful can be learned
  // from timing, and the database never contains a usable key.
  const [key] = await db
    .select({
      id: apiKeys.id,
      organizationId: apiKeys.organizationId,
      lastUsedAt: apiKeys.lastUsedAt,
    })
    .from(apiKeys)
    .where(and(eq(apiKeys.keyHash, sha256Hex(match[1]!)), isNull(apiKeys.revokedAt)))
    .limit(1);
  if (!key) return null;

  const now = Date.now();
  if (!key.lastUsedAt || now - key.lastUsedAt.getTime() > LAST_USED_REFRESH_MS) {
    await db
      .update(apiKeys)
      .set({ lastUsedAt: new Date(now) })
      .where(eq(apiKeys.id, key.id));
  }
  return { keyId: key.id, organizationId: key.organizationId };
}
