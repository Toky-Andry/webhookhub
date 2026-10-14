import { PGlite } from '@electric-sql/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import { migrate } from 'drizzle-orm/pglite/migrator';
import { Writable } from 'node:stream';
import { buildApp } from '../app.js';
import { authPlugin, SESSION_COOKIE, type AuthPluginOptions } from '../auth/plugin.js';
import * as schema from '../db/schema.js';

export async function createTestDb() {
  const client = new PGlite(); // in-memory PostgreSQL
  const db = drizzle(client, { schema });
  await migrate(db, { migrationsFolder: './drizzle' });
  return { db, close: () => client.close() };
}

export type TestDb = Awaited<ReturnType<typeof createTestDb>>['db'];

/** Collects everything the application logs, to check that no secret ends up there. */
export function captureLogs() {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk.toString());
      callback();
    },
  });
  return { stream, text: () => chunks.join('') };
}

export async function createTestApp(
  db: TestDb,
  overrides: Partial<AuthPluginOptions> = {},
  logger?: { stream: Writable; level: string },
) {
  const app = buildApp({ checkDb: async () => {}, logger: logger ?? false });
  await app.register(authPlugin, {
    db,
    sessionTtlHours: 24,
    secureCookies: false,
    // Generous limits so that ordinary tests never trip the rate limiter.
    limits: {
      login: { max: 1000, timeWindow: '1 minute' },
      register: { max: 1000, timeWindow: '1 minute' },
    },
    ...overrides,
  });
  await app.ready();
  return app;
}

export type TestApp = Awaited<ReturnType<typeof createTestApp>>;

export const STRONG_PASSWORD = 'correct-horse-battery-staple';

let counter = 0;
export function uniqueEmail(prefix = 'user') {
  counter += 1;
  return `${prefix}${counter}@example.com`;
}

/** Registers a user and returns the session cookie header to send on later requests. */
export async function registerUser(
  app: TestApp,
  options: { email?: string; password?: string; organizationName?: string } = {},
) {
  const email = options.email ?? uniqueEmail();
  const res = await app.inject({
    method: 'POST',
    url: '/v1/auth/register',
    payload: {
      email,
      password: options.password ?? STRONG_PASSWORD,
      organizationName: options.organizationName ?? 'Acme Corp',
    },
  });
  const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE);
  return {
    email,
    res,
    body: res.json() as { user: { id: string }; organization: { id: string } },
    cookieHeader: cookie ? `${SESSION_COOKIE}=${cookie.value}` : '',
    cookie,
  };
}
