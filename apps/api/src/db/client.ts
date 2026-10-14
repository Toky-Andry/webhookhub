import { drizzle } from 'drizzle-orm/node-postgres';
import type { PgDatabase } from 'drizzle-orm/pg-core';
import type { Pool } from 'pg';
import * as schema from './schema.js';

export function createDb(pool: Pool) {
  return drizzle(pool, { schema });
}

/**
 * Database type used by the application code. It is satisfied by the node-postgres driver
 * (production) and by PGlite (tests), so the same code runs in both.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Db = PgDatabase<any, typeof schema>;
