import { env } from '../config/env.js';
import { getStripeClient } from './stripeClient.js';

function buildPortalReturnUrl() {
  return (
    env.DASHBOARD_SUCCESS_URL ||
    env.APP_URL ||
    'http://localhost:3000'
  );
}

export async function createBillingPortalSession({
  stripeCustomerId,
  returnUrl = null,
} = {}) {
  const stripe = getStripeClient();

  if (!stripe) {
    throw new Error('Stripe is not configured');
  }

  if (!stripeCustomerId) {
    const error = new Error('stripeCustomerId is required');
    error.code = 'missing_stripe_customer_id';
    throw error;
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: stripeCustomerId,
    return_url: returnUrl || buildPortalReturnUrl(),
  });

  return {
    id: session.id,
    url: session.url,
    customer: stripeCustomerId,
  };
}

export function buildPortalResponse(session) {
  return {
    ok: true,
    portalSessionId: session.id,
    portalUrl: session.url,
    customer: session.customer,
  };
}