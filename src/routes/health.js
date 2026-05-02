import { env } from '../config/env.js';
import { getDatabaseStatus } from '../db/pool.js';
import { getTokenCacheStats } from '../cache/tokenMemoryCache.js';
import { getStripeStatus } from '../billing/stripeClient.js';

export async function buildHealthResponse({ pool = null } = {}) {
  const database = pool
    ? await getDatabaseStatus(pool)
    : {
        configured: Boolean(env.DATABASE_URL),
        connected: false,
        reason: 'pool_not_provided',
      };

  return {
    status: 'ok',
    name: 'ShieldAPI',
    version: env.VERSION || '4.8-dev',
    timestamp: new Date().toISOString(),
    environment: env.NODE_ENV || 'development',
    database,
    cache: getTokenCacheStats(),
    stripe: getStripeStatus(),
    modules: {
      config: true,
      db: true,
      cache: true,
      security: true,
      auth: true,
      billing: true,
      routes: true,
    },
  };
}

export async function handleHealth(req, res, context = {}) {
  const payload = await buildHealthResponse({
    pool: context.pool || null,
  });

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload, null, 2));
}