import { logger } from './logger.js';
import { incrementMetric } from './metrics.js';

export function normalizeError(error) {
  if (!error) {
    return {
      name: 'UnknownError',
      message: 'Unknown error',
    };
  }

  return {
    name: error.name || 'Error',
    message: error.message || String(error),
    code: error.code || null,
    statusCode: error.statusCode || null,
  };
}

export function reportError(error, {
  source = 'application',
  route = null,
  clientId = null,
  extra = {},
} = {}) {
  const normalized = normalizeError(error);

  incrementMetric('errors_total', {
    source,
    code: normalized.code || normalized.name,
  });

  logger.error('Error reported', {
    source,
    route,
    clientId,
    error: normalized,
    extra,
  });

  return normalized;
}
