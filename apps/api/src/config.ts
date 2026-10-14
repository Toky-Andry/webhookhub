import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  API_HOST: z.string().default('127.0.0.1'),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url(),
  // 32 random bytes, base64. Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
  ENCRYPTION_KEY: z.string().refine((v) => Buffer.from(v, 'base64').length === 32, {
    message: 'must be 32 random bytes encoded in base64',
  }),
  // Development only. Lets a destination be http or a private address (your own receiver).
  ALLOW_PRIVATE_DESTINATIONS: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  SESSION_TTL_HOURS: z.coerce
    .number()
    .int()
    .min(1)
    .max(24 * 90)
    .default(168),
});

export type Config = z.infer<typeof schema>;

/** Validates environment variables once at startup. Fails fast with a readable message. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid environment configuration: ${problems}`);
  }
  if (parsed.data.NODE_ENV === 'production' && parsed.data.ALLOW_PRIVATE_DESTINATIONS) {
    throw new Error(
      'Invalid environment configuration: ALLOW_PRIVATE_DESTINATIONS must be false in production',
    );
  }
  return parsed.data;
}
