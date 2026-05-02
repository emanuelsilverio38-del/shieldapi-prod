import { env } from '../config/env.js';
import { nowIso } from '../utils/time.js';

const tokenCache = new Map();

function getCacheKey(input) {
  if (!input || typeof input !== 'string') {
    return '';
  }

  return input.trim().toLowerCase();
}

export function getCachedAnalysis(input) {
  const key = getCacheKey(input);

  if (!key) {
    return null;
  }

  const cached = tokenCache.get(key);

  if (!cached) {
    return null;
  }

  const ageMs = Date.now() - cached.cachedAtMs;

  return {
    ...cached,
    ageMs,
    isFresh: ageMs <= env.CACHE_TTL_MS
  };
}

export function setCachedAnalysis(input, data) {
  const key = getCacheKey(input);

  if (!key) {
    return;
  }

  if (tokenCache.size >= env.CACHE_MAX_ITEMS && !tokenCache.has(key)) {
    const oldestKey = tokenCache.keys().next().value;

    if (oldestKey) {
      tokenCache.delete(oldestKey);
    }
  }

  tokenCache.set(key, {
    data,
    cachedAtMs: Date.now(),
    cachedAt: nowIso()
  });
}

export function buildCacheMeta(cached, mode, startedAt, responseTimeMs) {
  return {
    mode,
    cacheHit: true,
    dbHit: false,
    dataAgeSeconds: Math.round(cached.ageMs / 1000),
    responseTimeMs: responseTimeMs(startedAt)
  };
}

export function getTokenCacheStats() {
  return {
    items: tokenCache.size,
    maxItems: env.CACHE_MAX_ITEMS,
    ttlMs: env.CACHE_TTL_MS
  };
}

export function clearTokenCache() {
  tokenCache.clear();
}