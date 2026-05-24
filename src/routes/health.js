import { env } from '../config/env.js';
import { getDatabaseStatus } from '../db/pool.js';
import { getTokenCacheStats } from '../cache/tokenMemoryCache.js';
import { getStripeStatus } from '../billing/stripeClient.js';

function buildDatabaseStatus(context = {}) {
  if ('dbReady' in context || 'databaseEnabled' in context) {
    return {
      configured: Boolean(context.databaseEnabled ?? env.DATABASE_ENABLED),
      ready: Boolean(context.dbReady),
      lastError: context.dbLastError || null,
    };
  }

  return {
    configured: Boolean(env.DATABASE_URL),
    ready: false,
    lastError: null,
    reason: 'context_not_provided',
  };
}

function buildStripeStatus(context = {}) {
  const status = getStripeStatus();

  return {
    enabled: Boolean(context.stripeEnabled ?? status.configured),
    webhookConfigured: Boolean(
      context.stripeWebhookConfigured ?? status.webhookConfigured
    ),
    prices: status.prices,
  };
}

export async function buildHealthResponse(context = {}) {
  const database = ('dbReady' in context || 'databaseEnabled' in context)
    ? buildDatabaseStatus(context)
    : getDatabaseStatus();

  return {
    status: 'ok',
    name: env.SERVICE_NAME || 'ShieldAPI',
    version: context.version || env.VERSION,
    timestamp: new Date().toISOString(),
    environment: env.NODE_ENV || 'development',
    database,
    cache: getTokenCacheStats(),
    stripe: buildStripeStatus(context),
    routes: {
      modularRoutesReady: context.modularRoutesReady || null,
    },
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
  const payload = await buildHealthResponse(context);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload, null, 2));
}
