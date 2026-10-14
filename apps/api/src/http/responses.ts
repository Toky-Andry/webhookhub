import type { FastifyReply } from 'fastify';
import type { z } from 'zod';

export function error(code: string, message: string) {
  return { error: { code, message } };
}

export function invalid(reply: FastifyReply, issues: z.core.$ZodIssue[]) {
  // Only field names are returned, never the submitted values (they may contain secrets).
  const fields = [...new Set(issues.map((i) => i.path.join('.') || '(body)'))];
  return reply
    .code(400)
    .send({ error: { code: 'invalid_request', message: 'Invalid request', fields } });
}
