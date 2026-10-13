# WebhookHub

Reliable webhook delivery platform for SaaS and AI applications: signed payloads, automatic retries with exponential backoff and jitter, dead-letter queue, replay, and a delivery log.

> Status: work in progress (final-year project, Master 1).

## Quick start (development)

Requirements: Node.js 22+, pnpm, Docker Desktop.

```bash
cp .env.example .env        # then edit the "change-me" values
docker compose up -d        # PostgreSQL + Redis
pnpm install
pnpm dev:api                # http://127.0.0.1:3001/health
```

On Windows PowerShell, use `Copy-Item .env.example .env` instead of `cp`.

## Scripts

| Command          | Purpose              |
| ---------------- | -------------------- |
| `pnpm lint`      | ESLint               |
| `pnpm typecheck` | TypeScript, no emit  |
| `pnpm test`      | Unit tests (Vitest)  |
| `pnpm dev:api`   | API with auto-reload |

## Repository layout

```
apps/api         Fastify API
apps/worker      Delivery worker (coming)
apps/web         Dashboard (coming)
packages/shared  Constants and types shared by all apps
docs/design      Screenshots of the UI design
```

## License

MIT
