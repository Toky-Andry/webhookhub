import pg from 'pg';
import { buildApp } from './app.js';
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
