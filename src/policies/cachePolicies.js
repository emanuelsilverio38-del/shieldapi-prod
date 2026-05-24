export const CACHE_TTL_BY_STATUS_MS = {
  APPROVED: 60_000,
  WARNING: 120_000,
  BLOCKED: 300_000,
  ERROR: 30_000,
  UNKNOWN: 30_000,
};

export const CACHE_TTL_BY_EVENT_MS = {
  externalTimeout: 15_000,
  notIndexed: 30_000,
  dbFallback: 60_000,
};

export function getCacheTtlForAnalysis(analysis = {}) {
  const status = String(analysis.status || 'UNKNOWN').toUpperCase();

  return CACHE_TTL_BY_STATUS_MS[status] || CACHE_TTL_BY_STATUS_MS.UNKNOWN;
}

export function shouldCacheAnalysis(analysis = {}) {
  const status = String(analysis.status || '').toUpperCase();

  return Boolean(status) && status !== 'INTERNAL_ERROR';
}
