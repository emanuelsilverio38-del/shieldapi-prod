import {
  decideStatusFromRisk,
  getRiskLevelFromScore,
} from '../policies/riskPolicies.js';
import {
  SCORING_VERSION,
  clampScore,
  securityScoreFromRiskScore,
} from '../policies/scoringPolicies.js';

export function buildDecision({
  riskScore = 0,
  opportunityScore = 0,
  reasons = [],
  warnings = [],
  blockingReasons = [],
  criticalFlags = [],
} = {}) {
  const normalizedRiskScore = clampScore(riskScore);
  const status = blockingReasons.length > 0
    ? 'BLOCKED'
    : decideStatusFromRisk({
        riskScore: normalizedRiskScore,
        criticalFlags,
      });

  return {
    status,
    riskLevel: getRiskLevelFromScore(normalizedRiskScore),
    riskScore: normalizedRiskScore,
    securityScore: securityScoreFromRiskScore(normalizedRiskScore),
    opportunityScore: clampScore(opportunityScore),
    scoringVersion: SCORING_VERSION,
    reasons,
    warnings,
    blockingReasons,
  };
}
