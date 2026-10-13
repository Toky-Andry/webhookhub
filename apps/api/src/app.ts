import Fastify, { type FastifyInstance } from 'fastify';

export interface AppDeps {
  /** Resolves if the database answers, rejects otherwise. */
  checkDb: () => Promise<void>;
  logger?: boolean | object;
}

export function buildApp({ checkDb, logger = false }: AppDeps): FastifyInstance {
  const app = Fastify({ logger });

  app.get('/health', async (_request, reply) => {
    try {
      await checkDb();
      return { status: 'ok', db: 'up' };
    } catch (error) {
      app.log.error({ err: error }, 'database health check failed');
      return reply.code(503).send({ status: 'degraded', db: 'down' });
    }
  });

  return app;
}
