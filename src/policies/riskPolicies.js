export const RISK_LEVELS = {
  low: 'LOW',
  medium: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
};

export const DECISION_STATUS = {
  approved: 'APPROVED',
  warning: 'WARNING',
  blocked: 'BLOCKED',
};

export const RISK_THRESHOLDS = {
  approvedMaxRiskScore: 39,
  warningMinRiskScore: 40,
  blockedMinRiskScore: 80,
};

export const CRITICAL_RISK_FLAGS = [
  'BLACKLISTED_TOKEN',
  'BLACKLISTED_CREATOR',
  'FREEZE_AUTHORITY_ACTIVE',
  'MINT_AUTHORITY_ACTIVE',
  'EXTREME_HOLDER_CONCENTRATION',
  'RUGCHECK_SCAM_FLAG',
  'HONEYPOT_FLAG',
];

export function getRiskLevelFromScore(riskScore) {
  const score = Number(riskScore);

  if (!Number.isFinite(score)) return RISK_LEVELS.medium;
  if (score >= 90) return RISK_LEVELS.critical;
  if (score >= 70) return RISK_LEVELS.high;
  if (score >= 40) return RISK_LEVELS.medium;
  return RISK_LEVELS.low;
}

export function decideStatusFromRisk({
  riskScore = null,
  criticalFlags = [],
} = {}) {
  const flags = Array.isArray(criticalFlags) ? criticalFlags : [];
  const hasCriticalFlag = flags.some((flag) => CRITICAL_RISK_FLAGS.includes(flag));
  const score = Number(riskScore);

  if (hasCriticalFlag || (Number.isFinite(score) && score >= RISK_THRESHOLDS.blockedMinRiskScore)) {
    return DECISION_STATUS.blocked;
  }

  if (Number.isFinite(score) && score >= RISK_THRESHOLDS.warningMinRiskScore) {
    return DECISION_STATUS.warning;
  }

  return DECISION_STATUS.approved;
}
