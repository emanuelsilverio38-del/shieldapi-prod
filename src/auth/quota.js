import { getPlanConfig } from './plans.js';

function getPeriodStart(planConfig) {
  const now = new Date();

  if (planConfig?.quotaPeriod === 'day') {
    return new Date(Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate(),
      0,
      0,
      0,
      0
    ));
  }

  return new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    1,
    0,
    0,
    0,
    0
  ));
}

function getPeriodEnd(planConfig) {
  const now = new Date();

  if (planConfig?.quotaPeriod === 'day') {
    return new Date(Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate() + 1,
      0,
      0,
      0,
      0
    ));
  }

  return new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth() + 1,
    1,
    0,
    0,
    0,
    0
  ));
}

function normalizeQuotaLimit(planConfig) {
  const rawLimit =
    planConfig?.monthlyQuota ??
    planConfig?.quota ??
    planConfig?.requestsPerPeriod ??
    planConfig?.requestLimit ??
    null;

  if (rawLimit === null || rawLimit === undefined) return null;
  if (rawLimit === 'custom' || rawLimit === 'unlimited') return null;

  const numericLimit = Number(rawLimit);

  if (!Number.isFinite(numericLimit) || numericLimit <= 0) return null;

  return numericLimit;
}

export function getQuotaWindow(plan = 'free') {
  const planConfig = getPlanConfig(plan);

  return {
    plan,
    period: planConfig?.quotaPeriod || (plan === 'free' ? 'day' : 'month'),
    startsAt: getPeriodStart(planConfig).toISOString(),
    endsAt: getPeriodEnd(planConfig).toISOString(),
  };
}

export async function getClientUsageCount(pool, clientId, plan = 'free') {
  if (!pool || !clientId) {
    return 0;
  }

  const window = getQuotaWindow(plan);

  const result = await pool.query(
    `
    SELECT COUNT(*)::int AS count
    FROM api_usage_events
    WHERE client_id = $1
      AND created_at >= $2
      AND created_at < $3
    `,
    [clientId, window.startsAt, window.endsAt]
  );

  return Number(result.rows?.[0]?.count || 0);
}

export async function checkQuota({ pool, client } = {}) {
  if (!client) {
    return {
      allowed: false,
      reason: 'missing_client',
      plan: 'unknown',
      used: 0,
      limit: 0,
      remaining: 0,
    };
  }

  const plan = client.plan || 'free';
  const planConfig = getPlanConfig(plan);
  const limit = normalizeQuotaLimit(planConfig);
  const window = getQuotaWindow(plan);

  if (limit === null) {
    return {
      allowed: true,
      reason: 'unlimited_or_custom_quota',
      plan,
      used: 0,
      limit: null,
      remaining: null,
      period: window.period,
      periodStartsAt: window.startsAt,
      periodEndsAt: window.endsAt,
    };
  }

  const used = await getClientUsageCount(pool, client.id, plan);
  const remaining = Math.max(0, limit - used);

  return {
    allowed: used < limit,
    reason: used < limit ? 'quota_available' : 'quota_exceeded',
    plan,
    used,
    limit,
    remaining,
    period: window.period,
    periodStartsAt: window.startsAt,
    periodEndsAt: window.endsAt,
  };
}

export function buildQuotaResponse(quotaResult) {
  return {
    allowed: Boolean(quotaResult?.allowed),
    reason: quotaResult?.reason || 'unknown',
    plan: quotaResult?.plan || 'unknown',
    used: quotaResult?.used ?? 0,
    limit: quotaResult?.limit ?? null,
    remaining: quotaResult?.remaining ?? null,
    period: quotaResult?.period || null,
    periodStartsAt: quotaResult?.periodStartsAt || null,
    periodEndsAt: quotaResult?.periodEndsAt || null,
  };
}