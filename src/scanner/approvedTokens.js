const approvedTokens = new Map();

function getKey(token) {
  return String(token?.address || token?.tokenAddress || token?.symbol || token || '')
    .trim()
    .toLowerCase();
}

export function addApprovedToken(token, analysis = {}) {
  const key = getKey(token);
  if (!key) return null;

  const record = {
    key,
    token,
    analysis,
    approvedAt: new Date().toISOString(),
  };

  approvedTokens.set(key, record);
  return record;
}

export function listApprovedTokens() {
  return Array.from(approvedTokens.values());
}
