import { authenticateRequest } from './apiKeys.js';

export async function requireAdminAuth(req, context = {}) {
  const url = new URL(req.url, 'http://localhost');

  const auth = await authenticateRequest(req, url, {
    adminOnly: true,
    pool: context.pool || context.dbPool || null,
    dbReady: context.dbReady,
  });

  if (!auth.ok) {
    return {
      ok: false,
      statusCode: auth.statusCode || 401,
      error: auth.statusCode === 403 ? 'admin_forbidden' : 'authentication_required',
      message: auth.reason || 'Admin authentication is required.',
    };
  }

  return {
    ok: true,
    auth,
    client: auth.client,
    actorId: auth.master ? 'master' : auth.clientId,
  };
}
