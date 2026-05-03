import { readRequestBody, sendJson } from '../utils/http.js';
import { generateClientApiKey } from '../auth/apiKeys.js';
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

function requireAdmin(context = {}) {
  const client = context.client || null;

  if (!client) {
    return {
      ok: false,
      statusCode: 401,
      error: 'authentication_required',
      message: 'Admin authentication is required.',
    };
  }

  const plan = String(client.plan || '').toLowerCase();
  const isAdmin =
    plan === 'master' ||
    client.is_admin === true ||
    client.role === 'admin';

  if (!isAdmin) {
    return {
      ok: false,
      statusCode: 403,
      error: 'admin_required',
      message: 'This endpoint requires admin access.',
    };
  }

  return {
    ok: true,
    client,
  };
}

export async function handleAdminCreateClient(req, res, context = {}) {
  const auth = requireAdmin(context);

  if (!auth.ok) {
    return sendJson(res, auth.statusCode, auth);
  }

  try {
    const body = await readRequestBody(req);
    const apiKey = body.apiKey || generateClientApiKey();

    const client = await createClient(context.pool, {
      name: body.name,
      email: body.email || null,
      apiKey,
      plan: body.plan || 'free',
      billingStatus: body.billingStatus || 'manual',
      status: body.status || 'active',
      metadata: {
        createdBy: 'admin_route',
        adminClientId: auth.client.id,
        ...(body.metadata || {}),
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
  const auth = requireAdmin(context);

  if (!auth.ok) {
    return sendJson(res, auth.statusCode, auth);
  }

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
  const auth = requireAdmin(context);

  if (!auth.ok) {
    return sendJson(res, auth.statusCode, auth);
  }

  try {
    const body = await readRequestBody(req);
    const clientId = body.clientId || body.id;

    if (!clientId) {
      return sendJson(res, 400, {
        ok: false,
        error: 'missing_client_id',
        message: 'clientId is required.',
      });
    }

    const client = await disableClient(context.pool, clientId);

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
  const auth = requireAdmin(context);

  if (!auth.ok) {
    return sendJson(res, auth.statusCode, auth);
  }

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