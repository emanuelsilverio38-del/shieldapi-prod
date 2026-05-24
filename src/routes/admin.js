import { readRequestBody, sendJson } from '../utils/http.js';
import { generateClientApiKey } from '../auth/apiKeys.js';
import { requireAdminAuth } from '../auth/adminAuth.js';
import {
  validateCreateClientRequest,
  validateDisableClientRequest,
} from '../validators/adminValidator.js';
import { recordAuditEvent } from '../observability/auditLog.js';
import {
  createClient,
  disableClient,
  listClients,
} from '../db/clientsRepository.js';
import {
  getClientUsageSummary,
  getGlobalUsageSummary,
  getRecentUsageEvents,
} from '../db/usageRepository.js';

function requireDatabase(context = {}) {
  if (!context.pool || context.dbReady === false) {
    return {
      ok: false,
      statusCode: 503,
      error: 'database_not_ready',
      message: 'Database is not ready.',
    };
  }

  return { ok: true };
}

export async function handleAdminCreateClient(req, res, context = {}) {
  const auth = await requireAdminAuth(req, context);

  if (!auth.ok) {
    return sendJson(res, auth.statusCode, auth);
  }

  const database = requireDatabase(context);
  if (!database.ok) return sendJson(res, database.statusCode, database);

  try {
    const body = await readRequestBody(req);
    const validation = validateCreateClientRequest(body);

    if (!validation.ok) {
      return sendJson(res, 400, validation);
    }

    const apiKey = body.apiKey || generateClientApiKey();

    const client = await createClient(context.pool, {
      name: validation.name,
      email: validation.email,
      apiKey,
      plan: validation.plan,
      billingStatus: body.billingStatus || 'manual',
      status: validation.status,
      metadata: {
        createdBy: 'admin_route',
        adminActorId: auth.actorId,
        ...(body.metadata || {}),
      },
    });

    await recordAuditEvent({
      action: 'admin_client_created',
      actorId: auth.actorId,
      targetId: client.id,
      route: '/admin/clients/create',
      metadata: {
        plan: client.plan,
        status: client.status,
      },
    });

    return sendJson(res, 201, {
      ok: true,
      client,
      apiKey,
      warning: 'Store this API key now. It will not be shown again.',
    });
  } catch (error) {
    return sendJson(res, 400, {
      ok: false,
      error: 'create_client_failed',
      message: error.message,
    });
  }
}

export async function handleAdminListClients(req, res, context = {}) {
  const auth = await requireAdminAuth(req, context);

  if (!auth.ok) {
    return sendJson(res, auth.statusCode, auth);
  }

  const database = requireDatabase(context);
  if (!database.ok) return sendJson(res, database.statusCode, database);

  try {
    const clients = await listClients(context.pool, {
      limit: 100,
      offset: 0,
    });

    return sendJson(res, 200, {
      ok: true,
      count: clients.length,
      clients,
    });
  } catch (error) {
    return sendJson(res, 400, {
      ok: false,
      error: 'list_clients_failed',
      message: error.message,
    });
  }
}

export async function handleAdminDisableClient(req, res, context = {}) {
  const auth = await requireAdminAuth(req, context);

  if (!auth.ok) {
    return sendJson(res, auth.statusCode, auth);
  }

  const database = requireDatabase(context);
  if (!database.ok) return sendJson(res, database.statusCode, database);

  try {
    const body = await readRequestBody(req);
    const validation = validateDisableClientRequest(body);

    if (!validation.ok) return sendJson(res, 400, validation);

    const client = await disableClient(context.pool, validation.clientId);

    await recordAuditEvent({
      action: 'admin_client_disabled',
      actorId: auth.actorId,
      targetId: validation.clientId,
      route: '/admin/clients/disable',
    });

    return sendJson(res, 200, {
      ok: true,
      client,
    });
  } catch (error) {
    return sendJson(res, 400, {
      ok: false,
      error: 'disable_client_failed',
      message: error.message,
    });
  }
}

export async function handleAdminUsage(req, res, context = {}) {
  const auth = await requireAdminAuth(req, context);

  if (!auth.ok) {
    return sendJson(res, auth.statusCode, auth);
  }

  const database = requireDatabase(context);
  if (!database.ok) return sendJson(res, database.statusCode, database);

  try {
    const url = new URL(req.url, 'http://localhost');
    const clientId = url.searchParams.get('clientId');

    if (clientId) {
      const summary = await getClientUsageSummary(context.pool, clientId);

      return sendJson(res, 200, {
        ok: true,
        scope: 'client',
        clientId,
        usage: summary,
      });
    }

    const global = await getGlobalUsageSummary(context.pool, {
      limit: 20,
    });

    const recent = await getRecentUsageEvents(context.pool, {
      limit: 50,
    });

    return sendJson(res, 200, {
      ok: true,
      scope: 'global',
      usage: global,
      recent,
    });
  } catch (error) {
    return sendJson(res, 400, {
      ok: false,
      error: 'admin_usage_failed',
      message: error.message,
    });
  }
}

export function isAdminRoute(pathname) {
  return [
    '/admin/clients/create',
    '/admin/clients',
    '/admin/clients/disable',
    '/admin/clients/usage',
  ].includes(pathname);
}
