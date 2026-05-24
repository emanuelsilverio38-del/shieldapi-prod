export const SCORING_VERSION = 'v4.8.0-policy-draft';

export const RISK_SCORE_WEIGHTS = {
  dexLiquidity: 15,
  dexVolumeConsistency: 10,
  authorities: 25,
  holders: 20,
  creator: 15,
  metadata: 5,
  blacklist: 30,
  washTrading: 10,
};

export const OPPORTUNITY_SCORE_WEIGHTS = {
  liquidity: 25,
  volume24h: 25,
  transactionActivity: 20,
  buySellBalance: 10,
  pairAge: 10,
  marketCapFit: 10,
};

export function clampScore(value) {
  const score = Number(value);

  if (!Number.isFinite(score)) return 0;
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function securityScoreFromRiskScore(riskScore) {
  return clampScore(100 - Number(riskScore || 0));
}
