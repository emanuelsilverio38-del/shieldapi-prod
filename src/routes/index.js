import { handleRoot } from './root.js';
import { handleHealth } from './health.js';
import { handleDocs } from './docs.js';

import {
  handleCreateCheckoutSession,
  handleBillingPortal,
  handleBillingSuccess,
  handleBillingCancel,
  handleStripeWebhook,
} from './billing.js';
import {
  handleAdminCreateClient,
  handleAdminListClients,
  handleAdminDisableClient,
  handleAdminUsage,
} from './admin.js';
import {
  handleAnalyze,
  handleAnalyzeFast,
  handleSubmit,
  handleCacheStats,
  handleUsage,
} from './analyze.js';

export async function handleRoute(req, res, context = {}) {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  if (req.method === 'GET' && pathname === '/') {
    return handleRoot(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/health') {
    return handleHealth(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/docs') {
    return handleDocs(req, res, context);
  }

  if ((req.method === 'POST' || req.method === 'GET') && pathname === '/billing/create-checkout-session') {
    return handleCreateCheckoutSession(req, res, context);
  }

  if (req.method === 'POST' && pathname === '/billing/portal') {
    return handleBillingPortal(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/billing/success') {
    return handleBillingSuccess(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/billing/cancel') {
    return handleBillingCancel(req, res, context);
  }

  if (req.method === 'POST' && pathname === '/webhooks/stripe') {
    return handleStripeWebhook(req, res, context);
  }

  if (req.method === 'POST' && pathname === '/admin/clients/create') {
    return handleAdminCreateClient(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/admin/clients') {
    return handleAdminListClients(req, res, context);
  }

  if (req.method === 'POST' && pathname === '/admin/clients/disable') {
    return handleAdminDisableClient(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/admin/clients/usage') {
    return handleAdminUsage(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/analyze') {
    return handleAnalyze(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/analyze-fast') {
    return handleAnalyzeFast(req, res, context);
  }

  if (req.method === 'POST' && pathname === '/submit') {
    return handleSubmit(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/cache/stats') {
    return handleCacheStats(req, res, context);
  }

  if (req.method === 'GET' && pathname === '/usage') {
    return handleUsage(req, res, context);
  }

  return false;
}

export function getKnownRoutes() {
  return [
    'GET /',
    'GET /health',
    'GET /docs',
    'GET /analyze',
    'GET /analyze-fast',
    'POST /submit',
    'GET /cache/stats',
    'GET /usage',
    'POST /billing/create-checkout-session',
    'POST /billing/portal',
    'GET /billing/success',
    'GET /billing/cancel',
    'POST /webhooks/stripe',
    'POST /admin/clients/create',
    'GET /admin/clients',
    'POST /admin/clients/disable',
    'GET /admin/clients/usage',
  ];
}
