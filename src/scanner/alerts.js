export function buildScannerAlert({
  level = 'info',
  token = null,
  analysis = {},
  message = null,
} = {}) {
  return {
    level,
    token,
    status: analysis.status || null,
    riskScore: analysis.riskScore ?? null,
    securityScore: analysis.securityScore ?? null,
    opportunityScore: analysis.opportunityScore ?? null,
    message: message || `${analysis.status || 'UNKNOWN'} token detected`,
    createdAt: new Date().toISOString(),
  };
}

export function shouldAlertForAnalysis(analysis = {}, {
  minOpportunityScore = 70,
} = {}) {
  if (analysis.status === 'BLOCKED') return true;
  if (analysis.status === 'APPROVED' && Number(analysis.opportunityScore || 0) >= minOpportunityScore) return true;
  return false;
}
