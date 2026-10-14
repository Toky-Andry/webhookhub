import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The first test of a run can be slow on a busy machine (cold start of Fastify while the
    // in-memory PostgreSQL test is loading). 5 s is too tight for that.
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
