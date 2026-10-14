import { describe, expect, it } from 'vitest';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';

describe('GET /health', () => {
  it('returns 200 when the database is up', async () => {
    const app = buildApp({ checkDb: async () => {} });
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok', db: 'up' });
  });

  it('returns 503 when the database is down', async () => {
    const app = buildApp({
      checkDb: async () => {
        throw new Error('connection refused');
      },
    });
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({ status: 'degraded', db: 'down' });
  });
});

describe('loadConfig', () => {
  const base = {
    DATABASE_URL: 'postgres://u:p@127.0.0.1:5432/db',
    REDIS_URL: 'redis://127.0.0.1:6379',
    ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
  };

  it('rejects a missing DATABASE_URL', () => {
    expect(() => loadConfig({ ...base, DATABASE_URL: undefined })).toThrow(/DATABASE_URL/);
  });

  it('applies defaults', () => {
    const config = loadConfig(base);
    expect(config.API_PORT).toBe(3001);
    expect(config.API_HOST).toBe('127.0.0.1');
    expect(config.ALLOW_PRIVATE_DESTINATIONS).toBe(false);
  });

  it('rejects a missing or malformed ENCRYPTION_KEY', () => {
    expect(() => loadConfig({ ...base, ENCRYPTION_KEY: undefined })).toThrow(/ENCRYPTION_KEY/);
    expect(() => loadConfig({ ...base, ENCRYPTION_KEY: 'too-short' })).toThrow(/ENCRYPTION_KEY/);
  });

  it('refuses private destinations in production', () => {
    expect(() =>
      loadConfig({ ...base, NODE_ENV: 'production', ALLOW_PRIVATE_DESTINATIONS: 'true' }),
    ).toThrow(/production/);
    expect(
      loadConfig({ ...base, ALLOW_PRIVATE_DESTINATIONS: 'true' }).ALLOW_PRIVATE_DESTINATIONS,
    ).toBe(true);
  });
});
