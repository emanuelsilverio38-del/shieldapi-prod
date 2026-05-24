import { logger } from './logger.js';
import { incrementMetric } from './metrics.js';

export function createAuditEvent({
  action,
  actorId = null,
  targetId = null,
  route = null,
  metadata = {},
} = {}) {
  return {
    action: action || 'unknown_action',
    actorId,
    targetId,
    route,
    metadata,
    createdAt: new Date().toISOString(),
  };
}

export async function recordAuditEvent(event, {
  pool = null,
} = {}) {
  const auditEvent = createAuditEvent(event);

  incrementMetric('audit_events_total', {
    action: auditEvent.action,
  });

  logger.info('Audit event', auditEvent);

  if (pool) {
    // Persistent audit storage will be added when audit_log migrations land.
  }

  return auditEvent;
}
