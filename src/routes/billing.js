import { readRequestBody, readRawBody, sendHtml, sendJson } from '../utils/http.js';
import { createCheckoutSession, buildCheckoutResponse } from '../billing/checkout.js';
import { createBillingPortalSession, buildPortalResponse } from '../billing/portal.js';
import { constructStripeWebhookEvent, handleStripeWebhookEvent } from '../billing/webhook.js';

function getHeader(req, name) {
  const key = String(name).toLowerCase();
  return req?.headers?.[key] || req?.headers?.[name] || null;
}

export async function handleCreateCheckoutSession(req, res) {
  try {
    const body = await readRequestBody(req);

    const session = await createCheckoutSession({
      plan: body.plan || 'starter',
      email: body.email || null,
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
    const client = context.client || null;

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

export async function handleBillingSuccess(req, res) {
  return sendHtml(res, 200, `
    <!doctype html>
    <html>
      <head>
        <title>ShieldAPI Billing Success</title>
        <meta charset="utf-8" />
      </head>
      <body style="font-family: Arial, sans-serif; padding: 40px;">
        <h1>ShieldAPI subscription active</h1>
        <p>Your payment was completed successfully.</p>
        <p>If an API key was generated for this checkout, it will be shown by the current production handler until this route is fully connected.</p>
      </body>
    </html>
  `);
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