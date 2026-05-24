export function analyzeHolders({
  holderCount = null,
  top10Pct = null,
} = {}) {
  const concentration = Number(top10Pct);
  const warnings = [];
  const blockingReasons = [];

  if (Number.isFinite(concentration) && concentration >= 80) {
    blockingReasons.push('Top 10 holders concentration too high');
  } else if (Number.isFinite(concentration) && concentration >= 50) {
    warnings.push('Top 10 holders concentration is elevated');
  }

  return {
    checked: Number.isFinite(concentration) || Number.isFinite(Number(holderCount)),
    holderCount,
    top10Pct,
    risk: blockingReasons.length ? 'HIGH' : warnings.length ? 'MEDIUM' : 'LOW',
    warnings,
    blockingReasons,
  };
}
