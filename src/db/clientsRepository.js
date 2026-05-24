import crypto from 'crypto';

import { hashApiKey } from '../auth/apiKeys.js';
import { normalizePlan } from '../auth/plans.js';

export async function createClient(pool, {
  name,
  email = null,
  apiKey,
  plan = 'free',
  stripeCustomerId = null,
  stripeSubscriptionId = null,
  billingStatus = 'manual',
  status = 'active',
  metadata = {},
} = {}) {
  if (!pool) {
    throw new Error('Database pool is required');
  }

  if (!name) {
    throw new Error('Client name is required');
  }

  if (!apiKey) {
    throw new Error('API key is required');
  }

  const normalizedPlan = normalizePlan(plan);
  const apiKeyHash = hashApiKey(apiKey);
  const clientId = crypto.randomUUID();

  const result = await pool.query(
    `
    INSERT INTO api_clients (
      id,
      name,
      email,
      api_key_hash,
      plan,
      status,
      stripe_customer_id,
      stripe_subscription_id,
      billing_status,
      metadata,
      created_at,
      updated_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())
    RETURNING *
    `,
    [
      clientId,
      name,
      email,
      apiKeyHash,
      normalizedPlan,
      status,
      stripeCustomerId,
      stripeSubscriptionId,
      billingStatus,
      JSON.stringify(metadata || {}),
    ]
  );

  return result.rows[0];
}

export async function findClientById(pool, clientId) {
  if (!pool || !clientId) return null;

  const result = await pool.query(
    `
    SELECT *
    FROM api_clients
    WHERE id = $1
    LIMIT 1
    `,
    [clientId]
  );

  return result.rows[0] || null;
}

export async function findClientByEmail(pool, email) {
  if (!pool || !email) return null;

  const result = await pool.query(
    `
    SELECT *
    FROM api_clients
    WHERE LOWER(email) = LOWER($1)
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [email]
  );

  return result.rows[0] || null;
}

export async function findClientByStripeCustomerId(pool, stripeCustomerId) {
  if (!pool || !stripeCustomerId) return null;

  const result = await pool.query(
    `
    SELECT *
    FROM api_clients
    WHERE stripe_customer_id = $1
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [stripeCustomerId]
  );

  return result.rows[0] || null;
}

export async function findClientByStripeSubscriptionId(pool, stripeSubscriptionId) {
  if (!pool || !stripeSubscriptionId) return null;

  const result = await pool.query(
    `
    SELECT *
    FROM api_clients
    WHERE stripe_subscription_id = $1
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [stripeSubscriptionId]
  );

  return result.rows[0] || null;
}

export async function listClients(pool, { limit = 100, offset = 0, status = null, plan = null } = {}) {
  if (!pool) {
    throw new Error('Database pool is required');
  }

  const filters = [];
  const values = [];

  if (status) {
    values.push(status);
    filters.push(`status = $${values.length}`);
  }

  if (plan) {
    values.push(normalizePlan(plan));
    filters.push(`plan = $${values.length}`);
  }

  values.push(Number(limit));
  const limitParam = `$${values.length}`;

  values.push(Number(offset));
  const offsetParam = `$${values.length}`;

  const whereSql = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

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
      current_period_start,
      current_period_end,
      created_at,
      updated_at,
      metadata
    FROM api_clients
    ${whereSql}
    ORDER BY created_at DESC
    LIMIT ${limitParam}
    OFFSET ${offsetParam}
    `,
    values
  );

  return result.rows;
}

export async function updateClientBilling(pool, {
  clientId = null,
  stripeCustomerId = null,
  stripeSubscriptionId = null,
  plan = null,
  billingStatus = null,
  status = null,
  currentPeriodStart = null,
  currentPeriodEnd = null,
} = {}) {
  if (!pool) {
    throw new Error('Database pool is required');
  }

  if (!clientId && !stripeCustomerId && !stripeSubscriptionId) {
    throw new Error('clientId, stripeCustomerId or stripeSubscriptionId is required');
  }

  const updates = [];
  const values = [];

  if (plan) {
    values.push(normalizePlan(plan));
    updates.push(`plan = $${values.length}`);
  }

  if (billingStatus) {
    values.push(billingStatus);
    updates.push(`billing_status = $${values.length}`);
  }

  if (status) {
    values.push(status);
    updates.push(`status = $${values.length}`);
  }

  if (stripeCustomerId) {
    values.push(stripeCustomerId);
    updates.push(`stripe_customer_id = $${values.length}`);
  }

  if (stripeSubscriptionId) {
    values.push(stripeSubscriptionId);
    updates.push(`stripe_subscription_id = $${values.length}`);
  }

  if (currentPeriodStart) {
    values.push(currentPeriodStart);
    updates.push(`current_period_start = $${values.length}`);
  }

  if (currentPeriodEnd) {
    values.push(currentPeriodEnd);
    updates.push(`current_period_end = $${values.length}`);
  }

  updates.push('updated_at = NOW()');

  let whereSql;

  if (clientId) {
    values.push(clientId);
    whereSql = `id = $${values.length}`;
  } else if (stripeSubscriptionId) {
    values.push(stripeSubscriptionId);
    whereSql = `stripe_subscription_id = $${values.length}`;
  } else {
    values.push(stripeCustomerId);
    whereSql = `stripe_customer_id = $${values.length}`;
  }

  const result = await pool.query(
    `
    UPDATE api_clients
    SET ${updates.join(', ')}
    WHERE ${whereSql}
    RETURNING *
    `,
    values
  );

  return result.rows[0] || null;
}

export async function disableClient(pool, clientId) {
  if (!pool || !clientId) {
    throw new Error('Database pool and clientId are required');
  }

  const result = await pool.query(
    `
    UPDATE api_clients
    SET status = 'disabled',
        updated_at = NOW()
    WHERE id = $1
    RETURNING *
    `,
    [clientId]
  );

  return result.rows[0] || null;
}
