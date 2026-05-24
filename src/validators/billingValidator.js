import { getStripePriceForPlan, normalizePlan } from '../auth/plans.js';
import { validationError, validationOk } from './requestValidator.js';

const CHECKOUT_PLANS = new Set(['starter', 'pro', 'advanced']);

export function validateBillingPlan(plan) {
  const normalizedPlan = normalizePlan(plan || 'starter');

  if (!CHECKOUT_PLANS.has(normalizedPlan)) {
    return validationError(
      'INVALID_BILLING_PLAN',
      'Plan must be starter, pro or advanced.',
      {
        plan: normalizedPlan,
      }
    );
  }

  const priceId = getStripePriceForPlan(normalizedPlan);

  if (!priceId) {
    return validationError(
      'MISSING_STRIPE_PRICE',
      `Stripe price is not configured for plan ${normalizedPlan}.`,
      {
        plan: normalizedPlan,
      }
    );
  }

  return validationOk({
    plan: normalizedPlan,
    priceId,
  });
}

export function validateCheckoutRequest(body = {}, query = {}) {
  const plan = body.plan || query.plan || 'starter';
  const planResult = validateBillingPlan(plan);

  if (!planResult.ok) {
    return planResult;
  }

  const email = String(body.email || query.email || '').trim() || null;
  const name = String(body.name || query.name || '').trim() || null;

  return validationOk({
    plan: planResult.plan,
    priceId: planResult.priceId,
    email,
    name,
  });
}

export function validateStripeSessionId(sessionId) {
  const value = String(sessionId || '').trim();

  if (!value) {
    return validationError(
      'MISSING_STRIPE_SESSION_ID',
      'session_id is required.'
    );
  }

  if (!value.startsWith('cs_')) {
    return validationError(
      'INVALID_STRIPE_SESSION_ID',
      'session_id must be a Stripe Checkout session id.'
    );
  }

  return validationOk({
    sessionId: value,
  });
}

export function validateStripeCustomerId(customerId) {
  const value = String(customerId || '').trim();

  if (!value) {
    return validationError(
      'MISSING_STRIPE_CUSTOMER_ID',
      'Stripe customer id is required.'
    );
  }

  if (!value.startsWith('cus_')) {
    return validationError(
      'INVALID_STRIPE_CUSTOMER_ID',
      'Stripe customer id must start with cus_.'
    );
  }

  return validationOk({
    stripeCustomerId: value,
  });
}
