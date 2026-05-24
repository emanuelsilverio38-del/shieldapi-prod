export function analyzeCreator({
  previousSuspiciousTokens = 0,
  blacklisted = false,
} = {}) {
  const warnings = [];
  const blockingReasons = [];

  if (blacklisted) blockingReasons.push('Creator is blacklisted');
  if (previousSuspiciousTokens > 0) warnings.push('Creator has previous suspicious tokens');

  return {
    checked: blacklisted || previousSuspiciousTokens > 0,
    previousSuspiciousTokens,
    blacklisted,
    risk: blockingReasons.length ? 'HIGH' : warnings.length ? 'MEDIUM' : 'LOW',
    warnings,
    blockingReasons,
  };
}
