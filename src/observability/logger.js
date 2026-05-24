const SENSITIVE_KEY_PATTERN = /(api[_-]?key|authorization|stripe|secret|token|password)/i;

export function maskSensitiveValue(value) {
  const text = String(value || '');

  if (!text) return text;
  if (text.length <= 8) return '***';

  return `${text.slice(0, 6)}...${text.slice(-4)}`;
}

export function sanitizeLogPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    return payload;
  }

  if (Array.isArray(payload)) {
    return payload.map((item) => sanitizeLogPayload(item));
  }

  return Object.fromEntries(
    Object.entries(payload).map(([key, value]) => {
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        return [key, maskSensitiveValue(value)];
      }

      if (value && typeof value === 'object') {
        return [key, sanitizeLogPayload(value)];
      }

      return [key, value];
    })
  );
}

export function createLogger({
  service = 'ShieldAPI',
  level = 'info',
  sink = console,
} = {}) {
  const levels = ['debug', 'info', 'warn', 'error'];
  const minimumLevelIndex = levels.indexOf(level);

  function shouldLog(messageLevel) {
    const messageLevelIndex = levels.indexOf(messageLevel);
    return messageLevelIndex >= Math.max(0, minimumLevelIndex);
  }

  function write(messageLevel, message, payload = {}) {
    if (!shouldLog(messageLevel)) return;

    const entry = {
      timestamp: new Date().toISOString(),
      service,
      level: messageLevel,
      message,
      ...sanitizeLogPayload(payload),
    };

    const method = messageLevel === 'error'
      ? 'error'
      : messageLevel === 'warn'
        ? 'warn'
        : 'log';

    sink[method](JSON.stringify(entry));
  }

  return {
    debug: (message, payload) => write('debug', message, payload),
    info: (message, payload) => write('info', message, payload),
    warn: (message, payload) => write('warn', message, payload),
    error: (message, payload) => write('error', message, payload),
  };
}

export const logger = createLogger();
