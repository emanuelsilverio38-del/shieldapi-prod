export const BILLING_STATUSES = {
  active: 'active',
  trialing: 'trialing',
  pastDue: 'past_due',
  canceled: 'canceled',
  unpaid: 'unpaid',
  paymentFailed: 'payment_failed',
};

export const BILLING_POLICY = {
  paymentFailedBehavior: 'disable_after_grace_period',
  cancelBehavior: 'disable_at_period_end',
  gracePeriodDays: 3,
  upgradeBehavior: 'apply_immediately',
  downgradeBehavior: 'apply_at_period_end',
};

export function isBillingStatusActive(status) {
  return [BILLING_STATUSES.active, BILLING_STATUSES.trialing].includes(
    String(status || '').toLowerCase()
  );
}

export function shouldDisableForBillingStatus(status) {
  const normalized = String(status || '').toLowerCase();

  return [
    BILLING_STATUSES.canceled,
    BILLING_STATUSES.unpaid,
    BILLING_STATUSES.paymentFailed,
  ].includes(normalized);
}

export function getBillingPolicy() {
  return {
    ...BILLING_POLICY,
  };
}
