export function analyzeMetadata({
  mutable = null,
  suspiciousLinks = [],
  spoofRisk = false,
} = {}) {
  const warnings = [];
  const blockingReasons = [];

  if (mutable === true) warnings.push('Token metadata is mutable');
  if (suspiciousLinks.length > 0) warnings.push('Token metadata contains suspicious links');
  if (spoofRisk) blockingReasons.push('Token metadata has spoof risk');

  return {
    checked: mutable !== null || suspiciousLinks.length > 0 || spoofRisk,
    mutable,
    suspiciousLinks,
    spoofRisk,
    risk: blockingReasons.length ? 'HIGH' : warnings.length ? 'MEDIUM' : 'LOW',
    warnings,
    blockingReasons,
  };
}
