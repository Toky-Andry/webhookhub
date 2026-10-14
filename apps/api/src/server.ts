import pg from 'pg';
import { authPlugin } from './auth/plugin.js';
import { buildApp } from './app.js';
import { createDb } from './db/client.js';
import { parseEncryptionKey } from './security/crypto.js';
import { loadConfig } from './config.js';

const config = loadConfig();

const pool = new pg.Pool({ connectionString: config.DATABASE_URL, max: 5 });

const app = buildApp({
  checkDb: async () => {
    await pool.query('SELECT 1');
  },
  logger: {
    level: config.NODE_ENV === 'production' ? 'info' : 'debug',
    // Never log credentials.
    redact: ['req.headers.authorization', 'req.headers.cookie'],
  },
});

await app.register(authPlugin, {
  db: createDb(pool),
  sessionTtlHours: config.SESSION_TTL_HOURS,
  secureCookies: config.NODE_ENV === 'production',
  encryptionKey: parseEncryptionKey(config.ENCRYPTION_KEY),
  allowPrivateDestinations: config.ALLOW_PRIVATE_DESTINATIONS,
});

async function shutdown(signal: string) {
  app.log.info({ signal }, 'shutting down');
  await app.close();
  await pool.end();
  process.exit(0);
}
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

try {
  await app.listen({ host: config.API_HOST, port: config.API_PORT });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
