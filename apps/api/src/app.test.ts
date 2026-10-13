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
  it('rejects a missing DATABASE_URL', () => {
    expect(() => loadConfig({ REDIS_URL: 'redis://127.0.0.1:6379' })).toThrow(/DATABASE_URL/);
  });

  it('applies defaults', () => {
    const config = loadConfig({
      DATABASE_URL: 'postgres://u:p@127.0.0.1:5432/db',
      REDIS_URL: 'redis://127.0.0.1:6379',
    });
    expect(config.API_PORT).toBe(3001);
    expect(config.API_HOST).toBe('127.0.0.1');
  });
});
