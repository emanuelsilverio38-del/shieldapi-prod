import { readRequestBody, readRawBody, sendHtml, sendJson } from '../utils/http.js';
import { createCheckoutSession, buildCheckoutResponse } from '../billing/checkout.js';
import { createBillingPortalSession, buildPortalResponse } from '../billing/portal.js';
import { getStripeClient } from '../billing/stripeClient.js';
import {
  constructStripeWebhookEvent,
  handleCheckoutSessionCompleted,
  handleStripeWebhookEvent,
} from '../billing/webhook.js';
import { consumeApiKeyDelivery } from '../billing/apiKeyDelivery.js';
import { authenticateRequest } from '../auth/apiKeys.js';

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getHeader(req, name) {
  const key = String(name).toLowerCase();
  return req?.headers?.[key] || req?.headers?.[name] || null;
}

function getUrl(req) {
  return new URL(req.url, 'http://localhost');
}

export async function handleCreateCheckoutSession(req, res) {
  try {
    const url = getUrl(req);
    const body = req.method === 'POST' ? await readRequestBody(req) : {};

    const session = await createCheckoutSession({
      plan: body.plan || url.searchParams.get('plan') || 'starter',
      email: body.email || url.searchParams.get('email') || null,
      clientReferenceId: body.clientReferenceId || null,
      metadata: body.metadata || {},
    });

    return sendJson(res, 200, buildCheckoutResponse(session));
  } catch (error) {
    return sendJson(res, 400, {
      ok: false,
      error: error.code || 'checkout_session_failed',
      message: error.message,
    });
  }
}

export async function handleBillingPortal(req, res, context = {}) {
  try {
    const auth = await authenticateRequest(req, getUrl(req), {
      pool: context.pool || context.dbPool || null,
      dbReady: context.dbReady,
    });

    if (!auth.ok) {
      return sendJson(res, auth.statusCode || 401, {
        ok: false,
        error: auth.statusCode === 403 ? 'forbidden' : 'authentication_required',
        message: auth.reason || 'Valid API key is required.',
      });
    }

    const client = auth.client || null;

    const stripeCustomerId =
      client?.stripe_customer_id ||
      client?.stripeCustomerId ||
      null;

    const session = await createBillingPortalSession({
      stripeCustomerId,
    });

    return sendJson(res, 200, buildPortalResponse(session));
  } catch (error) {
    return sendJson(res, 400, {
      ok: false,
      error: error.code || 'billing_portal_failed',
      message: error.message,
    });
  }
}

export async function handleBillingSuccess(req, res, context = {}) {
  const url = getUrl(req);
  const sessionId = url.searchParams.get('session_id');

  if (!sessionId) {
    return sendHtml(res, 200, '<h1>Payment received</h1><p>No session_id found. Contact support.</p>');
  }

  try {
    const stripe = getStripeClient();
    if (!stripe) throw new Error('Stripe is not configured');

    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['subscription', 'line_items.data.price'],
    });

    const result = await handleCheckoutSessionCompleted(context.pool, session);
    const delivery = await consumeApiKeyDelivery(context.pool, sessionId);
    const apiKey = delivery?.api_key || result.apiKey || null;
    const appUrl = context.appUrl || 'https://zucchini-caring-production.up.railway.app';

    return sendHtml(res, 200, `
      <!doctype html>
      <html>
        <head>
          <title>ShieldAPI - Payment Success</title>
          <meta charset="utf-8" />
        </head>
        <body style="font-family:Arial,sans-serif;max-width:760px;margin:60px auto;padding:20px;line-height:1.5;">
          <h1>ShieldAPI payment successful</h1>
          <p>Your plan is now active: <strong>${escapeHtml(result.plan || session.metadata?.plan || 'starter')}</strong></p>
          ${apiKey ? `<p><strong>Save your API key now. It will not be shown again:</strong></p><pre style="background:#111;color:#0f0;padding:16px;border-radius:8px;white-space:pre-wrap;">${escapeHtml(apiKey)}</pre>` : '<p>Your client was activated. If you already had an API key, keep using the existing one.</p>'}
          <p>Use it with:</p>
          <pre style="background:#f4f4f4;padding:16px;border-radius:8px;white-space:pre-wrap;">${escapeHtml(appUrl)}/usage?key=YOUR_API_KEY</pre>
        </body>
      </html>
    `);
  } catch (error) {
    return sendHtml(res, 500, `<h1>Payment success, but activation failed</h1><p>${escapeHtml(error.message)}</p>`);
  }
}

export async function handleBillingCancel(req, res) {
  return sendHtml(res, 200, `
    <!doctype html>
    <html>
      <head>
        <title>ShieldAPI Billing Cancelled</title>
        <meta charset="utf-8" />
      </head>
      <body style="font-family: Arial, sans-serif; padding: 40px;">
        <h1>Checkout cancelled</h1>
        <p>No subscription was activated.</p>
      </body>
    </html>
  `);
}

export async function handleStripeWebhook(req, res, context = {}) {
  try {
    const rawBody = await readRawBody(req);
    const signature = getHeader(req, 'stripe-signature');

    const event = constructStripeWebhookEvent(rawBody, signature);
    const result = await handleStripeWebhookEvent(context.pool, event);

    return sendJson(res, 200, {
      received: true,
      ...result,
    });
  } catch (error) {
    return sendJson(res, 400, {
      received: false,
      error: 'stripe_webhook_failed',
      message: error.message,
    });
  }
}

export function isBillingRoute(pathname) {
  return [
    '/billing/create-checkout-session',
    '/billing/portal',
    '/billing/success',
    '/billing/cancel',
    '/webhooks/stripe',
  ].includes(pathname);
}
