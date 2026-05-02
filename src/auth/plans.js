import { env } from '../config/env.js';

export const PLAN_CONFIG = {
  free: {
    name: 'Free',
    perMinute: 30,
    quota: 100,
    quotaPeriod: 'day'
  },
  starter: {
    name: 'Starter',
    perMinute: 120,
    quota: 10_000,
    quotaPeriod: 'month',
    stripePriceId: env.STRIPE_PRICE_STARTER
  },
  pro: {
    name: 'Pro',
    perMinute: 600,
    quota: 100_000,
    quotaPeriod: 'month',
    stripePriceId: env.STRIPE_PRICE_PRO
  },
  advanced: {
    name: 'Advanced',
    perMinute: 1500,
    quota: 500_000,
    quotaPeriod: 'month',
    stripePriceId: env.STRIPE_PRICE_ADVANCED
  },
  enterprise: {
    name: 'Enterprise',
    perMinute: env.ENTERPRISE_RATE_LIMIT_PER_MINUTE,
    quota: null,
    quotaPeriod: 'month'
  },
  master: {
    name: 'Master Admin',
    perMinute: env.MASTER_RATE_LIMIT_PER_MINUTE,
    quota: null,
    quotaPeriod: 'month'
  }
};

export function normalizePlan(plan) {
  const normalized = String(plan || 'free').toLowerCase().trim();

  if (PLAN_CONFIG[normalized]) {
    return normalized;
  }

  return 'free';
}

export function getPlanConfig(plan) {
  return PLAN_CONFIG[normalizePlan(plan)] || PLAN_CONFIG.free;
}

export function getPlanByStripePriceId(priceId) {
  if (!priceId) {
    return null;
  }

  for (const [plan, config] of Object.entries(PLAN_CONFIG)) {
    if (config.stripePriceId && config.stripePriceId === priceId) {
      return plan;
    }
  }

  return null;
}

export function getStripePriceForPlan(plan) {
  const normalized = normalizePlan(plan);
  const config = getPlanConfig(normalized);

  return config.stripePriceId || '';
}

export function getPublicPlans() {
  return Object.fromEntries(
    Object.entries(PLAN_CONFIG).map(([key, value]) => [
      key,
      {
        perMinute: value.perMinute,
        quota: value.quota,
        quotaPeriod: value.quotaPeriod,
        stripeConfigured: Boolean(value.stripePriceId)
      }
    ])
  );
}