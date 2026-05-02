import Stripe from 'stripe';
import { env } from '../config/env.js';

let stripeInstance = null;

export function isStripeConfigured() {
  return Boolean(env.STRIPE_SECRET_KEY);
}

export function getStripeClient() {
  if (!isStripeConfigured()) {
    return null;
  }

  if (!stripeInstance) {
    stripeInstance = new Stripe(env.STRIPE_SECRET_KEY, {
      apiVersion: '2024-06-20',
    });
  }

  return stripeInstance;
}

export function getStripeStatus() {
  return {
    configured: isStripeConfigured(),
    webhookConfigured: Boolean(env.STRIPE_WEBHOOK_SECRET),
    prices: {
      starter: Boolean(env.STRIPE_PRICE_STARTER),
      pro: Boolean(env.STRIPE_PRICE_PRO),
      advanced: Boolean(env.STRIPE_PRICE_ADVANCED),
    },
  };
}

export function resetStripeClientForTests() {
  stripeInstance = null;
}