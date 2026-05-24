import { recordExternalApiMetric } from './metrics.js';

export function buildExternalApiEvent({
  provider,
  ok,
  statusCode = null,
  latencyMs = null,
  error = null,
} = {}) {
  return {
    provider: provider || 'unknown',
    ok: Boolean(ok),
    status: ok ? 'success' : 'failed',
    statusCode,
    latencyMs,
    error: error?.message || error || null,
    checkedAt: new Date().toISOString(),
  };
}

export function recordExternalApiCall(event = {}) {
  const normalized = buildExternalApiEvent(event);
  recordExternalApiMetric(normalized.provider, normalized.status);
  return normalized;
}
