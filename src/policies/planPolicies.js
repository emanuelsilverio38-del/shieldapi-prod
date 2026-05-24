export const PLAN_POLICIES = {
  free: {
    name: 'Free',
    quota: 100,
    quotaPeriod: 'day',
    perMinute: 30,
  },
  starter: {
    name: 'Starter',
    quota: 10_000,
    quotaPeriod: 'month',
    perMinute: 120,
  },
  pro: {
    name: 'Pro',
    quota: 100_000,
    quotaPeriod: 'month',
    perMinute: 600,
  },
  advanced: {
    name: 'Advanced',
    quota: 500_000,
    quotaPeriod: 'month',
    perMinute: 1500,
  },
  enterprise: {
    name: 'Enterprise',
    quota: null,
    quotaPeriod: 'month',
    perMinute: 5000,
    custom: true,
  },
  master: {
    name: 'Master Admin',
    quota: null,
    quotaPeriod: 'month',
    perMinute: 5000,
    internal: true,
  },
};

export function normalizePolicyPlan(plan) {
  const normalized = String(plan || 'free').toLowerCase().trim();
  return PLAN_POLICIES[normalized] ? normalized : 'free';
}

export function getPlanPolicy(plan) {
  return PLAN_POLICIES[normalizePolicyPlan(plan)];
}

export function isPlanQuotaUnlimited(plan) {
  return getPlanPolicy(plan).quota === null;
}
