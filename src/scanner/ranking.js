function scoreNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function getScannerRankScore(analysis = {}) {
  const securityScore = scoreNumber(analysis.securityScore ?? (100 - scoreNumber(analysis.riskScore)));
  const opportunityScore = scoreNumber(analysis.opportunityScore);
  const riskPenalty = scoreNumber(analysis.riskScore) * 0.7;
  const blockingPenalty = Array.isArray(analysis.blockingReasons) && analysis.blockingReasons.length > 0
    ? 100
    : 0;

  return Math.max(0, Math.round((securityScore * 0.55) + (opportunityScore * 0.45) - riskPenalty - blockingPenalty));
}

export function rankScannerCandidates(candidates = []) {
  return [...candidates]
    .map((candidate) => ({
      ...candidate,
      scannerRankScore: getScannerRankScore(candidate.analysis || candidate),
    }))
    .sort((a, b) => b.scannerRankScore - a.scannerRankScore);
}
