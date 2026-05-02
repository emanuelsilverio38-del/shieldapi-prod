import { env } from '../config/env.js';
import { getStripeClient } from './stripeClient.js';
import { getPlanConfig, getStripePriceForPlan, normalizePlan } from '../auth/plans.js';

function buildSuccessUrl(plan) {
  const baseUrl =
    env.DASHBOARD_SUCCESS_URL ||
    `${env.APP_URL || 'http://localhost:3000'}/billing/success`;

  const separator = baseUrl.includes('?') ? '&' : '?';

  if (baseUrl.includes('session_id=')) {
    return baseUrl;
  }

  return `${baseUrl}${separator}session_id={CHECKOUT_SESSION_ID}&plan=${encodeURIComponent(plan)}`;
}

function buildCancelUrl(plan) {
  const baseUrl =
    env.DASHBOARD_CANCEL_URL ||
    `${env.APP_URL || 'http://localhost:3000'}/billing/cancel`;

  const separator = baseUrl.includes('?') ? '&' : '?';

  return `${baseUrl}${separator}plan=${encodeURIComponent(plan)}`;
}

export function validateCheckoutPlan(plan) {
  const normalizedPlan = normalizePlan(plan);

  if (!['starter', 'pro', 'advanced'].includes(normalizedPlan)) {
    return {
      valid: false,
      plan: normalizedPlan,
      reason: 'invalid_checkout_plan',
      message: 'Plan must be starter, pro or advanced.',
    };
  }

  const priceId = getStripePriceForPlan(normalizedPlan);

  if (!priceId) {
    return {
      valid: false,
      plan: normalizedPlan,
      reason: 'missing_stripe_price',
      message: `Stripe price is not configured for plan ${normalizedPlan}.`,
    };
  }

  return {
    valid: true,
    plan: normalizedPlan,
    priceId,
    planConfig: getPlanConfig(normalizedPlan),
  };
}

export async function createCheckoutSession({
  plan = 'starter',
  email = null,
  clientReferenceId = null,
  metadata = {},
} = {}) {
  const stripe = getStripeClient();

  if (!stripe) {
    throw new Error('Stripe is not configured');
  }

  const validation = validateCheckoutPlan(plan);

  if (!validation.valid) {
    const error = new Error(validation.message);
    error.code = validation.reason;
    error.plan = validation.plan;
    throw error;
  }

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    customer_email: email || undefined,
    client_reference_id: clientReferenceId || undefined,
    line_items: [
      {
        price: validation.priceId,
        quantity: 1,
      },
    ],
    success_url: buildSuccessUrl(validation.plan),
    cancel_url: buildCancelUrl(validation.plan),
    metadata: {
      plan: validation.plan,
      source: 'shieldapi_checkout',
      ...metadata,
    },
    subscription_data: {
      metadata: {
        plan: validation.plan,
        source: 'shieldapi_checkout',
        ...metadata,
      },
    },
    allow_promotion_codes: true,
  });

  return {
    id: session.id,
    url: session.url,
    plan: validation.plan,
    priceId: validation.priceId,
    status: session.status,
  };
}

export function buildCheckoutResponse(session) {
  return {
    ok: true,
    checkoutSessionId: session.id,
    checkoutUrl: session.url,
    plan: session.plan,
    priceId: session.priceId,
    status: session.status,
  };
}