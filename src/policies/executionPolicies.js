export const EXECUTION_POLICY = {
  enabled: false,
  maxSlippageBps: 500,
  maxPriceImpactPct: 5,
  minLiquidityUsd: 25_000,
  allowWarningWithExplicitConfirmation: true,
  blockedStatusCanPrepareSwap: false,
};

export function canPrepareSwapForDecision(status, {
  warningAccepted = false,
} = {}) {
  const normalized = String(status || '').toUpperCase();

  if (normalized === 'BLOCKED') return false;
  if (normalized === 'WARNING') {
    return EXECUTION_POLICY.allowWarningWithExplicitConfirmation && warningAccepted;
  }

  return normalized === 'APPROVED';
}

export function getExecutionPolicy() {
  return {
    ...EXECUTION_POLICY,
  };
}
