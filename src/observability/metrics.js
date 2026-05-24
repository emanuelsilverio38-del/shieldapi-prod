const counters = new Map();

function metricKey(name, labels = {}) {
  const labelText = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join(',');

  return labelText ? `${name}{${labelText}}` : name;
}

export function incrementMetric(name, labels = {}, amount = 1) {
  const key = metricKey(name, labels);
  counters.set(key, Number(counters.get(key) || 0) + amount);
  return counters.get(key);
}

export function getMetric(name, labels = {}) {
  return Number(counters.get(metricKey(name, labels)) || 0);
}

export function getAllMetrics() {
  return Object.fromEntries(counters.entries());
}

export function resetMetrics() {
  counters.clear();
}

export function recordRouteMetric(route, statusCode) {
  incrementMetric('requests_total', { route, statusCode });
}

export function recordCacheMetric(type) {
  incrementMetric('cache_events_total', { type });
}

export function recordExternalApiMetric(provider, status) {
  incrementMetric('external_api_events_total', { provider, status });
}
