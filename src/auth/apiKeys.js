import crypto from 'crypto';

import { env } from '../config/env.js';
import { dbPool, dbReady } from '../db/pool.js';
import { getPlanConfig, normalizePlan, PLAN_CONFIG } from './plans.js';

export function hashApiKey(apiKey) {
  return crypto.createHash('sha256').update(String(apiKey)).digest('hex');
}

export function generateClientApiKey() {
  return `shield_live_${crypto.randomBytes(24).toString('hex')}`;
}

export function getAuthKey(req, urlObj) {
  const keyFromQuery = urlObj.searchParams.get('key');
  const keyFromHeader = req.headers['x-api-key'];
  const authorization = req.headers.authorization || '';
  const bearer = authorization.replace(/^Bearer\s+/i, '');

  return keyFromQuery || keyFromHeader || bearer || '';
}

export function getPublicClient(client) {
  if (!client) {
    return null;
  }

  return {
    id: client.id,
    name: client.name,
    email: client.email || null,
    plan: client.plan,
    status: client.status,
    billingStatus: client.billing_status || null,
    currentPeriodEnd: client.current_period_end || null,
    stripeCustomerId: client.stripe_customer_id || null,
    stripeSubscriptionId: client.stripe_subscription_id || null,
    createdAt: client.created_at || client.createdAt || null,
    lastUsedAt: client.last_used_at || client.lastUsedAt || null,
    disabledAt: client.disabled_at || client.disabledAt || null
  };
}

export function isBillingActive(client) {
  if (!client) {
    return false;
  }

  if (!client.billing_status) {
    return true;
  }

  return ['active', 'trialing', 'manual'].includes(client.billing_status);
}

export function isClientPeriodValid(client) {
  if (!client?.current_period_end) {
    return true;
  }

  return new Date(client.current_period_end).getTime() > Date.now();
}

export async function findClientByApiKey(apiKey, {
  pool = dbPool,
  ready = dbReady,
} = {}) {
  if (!pool || !ready || !apiKey) {
    return null;
  }

  const apiKeyHash = hashApiKey(apiKey);

  try {
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        plan,
        status,
        billing_status,
        stripe_customer_id,
        stripe_subscription_id,
        stripe_price_id,
        current_period_end,
        created_at,
        updated_at,
        last_used_at,
        disabled_at
      FROM api_clients
      WHERE api_key_hash = $1
      LIMIT 1
      `,
      [apiKeyHash]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return result.rows[0];
  } catch (error) {
    console.log('[AUTH] Failed to find client:', error.message);
    return null;
  }
}

export async function disableClientById(clientId, billingStatus = 'disabled', {
  pool = dbPool,
  ready = dbReady,
} = {}) {
  if (!pool || !ready || !clientId) {
    return false;
  }

  await pool.query(
    `
    UPDATE api_clients
    SET
      status = 'disabled',
      billing_status = $2,
      disabled_at = NOW(),
      updated_at = NOW()
    WHERE id = $1
    `,
    [clientId, billingStatus]
  );

  return true;
}

export async function authenticateRequest(req, urlObj, options = {}) {
  const providedKey = getAuthKey(req, urlObj);
  const master = Boolean(env.API_KEY && providedKey === env.API_KEY);
  const pool = options.pool || dbPool;
  const ready = options.dbReady ?? options.ready ?? dbReady;

  if (master) {
    return {
      ok: true,
      type: 'master',
      master: true,
      client: null,
      clientId: null,
      clientName: 'MASTER',
      plan: 'master',
      planConfig: PLAN_CONFIG.master,
      identity: 'master'
    };
  }

  if (options.adminOnly) {
    return {
      ok: false,
      statusCode: 401,
      reason: 'Admin API key required'
    };
  }

  const client = await findClientByApiKey(providedKey, {
    pool,
    ready,
  });

  if (!client) {
    return {
      ok: false,
      statusCode: 401,
      reason: 'API key missing or invalid'
    };
  }

  if (client.status !== 'active') {
    return {
      ok: false,
      statusCode: 403,
      reason: 'API key is disabled'
    };
  }

  if (!isBillingActive(client)) {
    return {
      ok: false,
      statusCode: 403,
      reason: `Billing status is ${client.billing_status}`
    };
  }

  if (!isClientPeriodValid(client)) {
    disableClientById(client.id, 'expired', {
      pool,
      ready,
    }).catch(() => {});

    return {
      ok: false,
      statusCode: 403,
      reason: 'Subscription expired'
    };
  }

  const plan = normalizePlan(client.plan);

  return {
    ok: true,
    type: 'client',
    master: false,
    client,
    clientId: client.id,
    clientName: client.name,
    plan,
    planConfig: getPlanConfig(plan),
    identity: `client:${client.id}`
  };
}
