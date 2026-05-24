import { getPlanConfig } from './plans.js';

const rateLimitStore = new Map();

function nowMs() {
  return Date.now();
}

function getClientRateKey(client, req) {
  if (client?.id) return `client:${client.id}`;

  const ip =
    req?.headers?.['x-forwarded-for']?.split(',')[0]?.trim() ||
    req?.socket?.remoteAddress ||
    'unknown';

  return `ip:${ip}`;
}

function cleanupOldRateLimitEntries(currentTime = nowMs()) {
  for (const [key, value] of rateLimitStore.entries()) {
    if (!value?.windowEndsAt || value.windowEndsAt < currentTime) {
      rateLimitStore.delete(key);
    }
  }
}

export function checkRateLimit({ client = null, req = null, plan = null } = {}) {
  const currentTime = nowMs();

  cleanupOldRateLimitEntries(currentTime);

  const effectivePlan = plan || client?.plan || 'free';
  const planConfig = getPlanConfig(effectivePlan);

  const limitPerMinute = Number(
    planConfig?.rateLimitPerMinute ??
    planConfig?.perMinute ??
    30
  );
  const windowMs = 60 * 1000;

  const key = getClientRateKey(client, req);

  const existing = rateLimitStore.get(key);

  if (!existing || existing.windowEndsAt <= currentTime) {
    const freshEntry = {
      count: 1,
      limit: limitPerMinute,
      windowStartedAt: currentTime,
      windowEndsAt: currentTime + windowMs,
    };

    rateLimitStore.set(key, freshEntry);

    return {
      allowed: true,
      key,
      count: freshEntry.count,
      limit: freshEntry.limit,
      remaining: Math.max(0, freshEntry.limit - freshEntry.count),
      resetAt: new Date(freshEntry.windowEndsAt).toISOString(),
      retryAfterSeconds: 0,
    };
  }

  existing.count += 1;
  existing.limit = limitPerMinute;

  const allowed = existing.count <= limitPerMinute;
  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((existing.windowEndsAt - currentTime) / 1000)
  );

  rateLimitStore.set(key, existing);

  return {
    allowed,
    key,
    count: existing.count,
    limit: existing.limit,
    remaining: Math.max(0, existing.limit - existing.count),
    resetAt: new Date(existing.windowEndsAt).toISOString(),
    retryAfterSeconds: allowed ? 0 : retryAfterSeconds,
  };
}

export function getRateLimitStats() {
  cleanupOldRateLimitEntries();

  return {
    activeWindows: rateLimitStore.size,
    entries: Array.from(rateLimitStore.entries()).map(([key, value]) => ({
      key,
      count: value.count,
      limit: value.limit,
      resetAt: new Date(value.windowEndsAt).toISOString(),
    })),
  };
}

export function clearRateLimitStore() {
  rateLimitStore.clear();

  return {
    cleared: true,
    activeWindows: rateLimitStore.size,
  };
}
