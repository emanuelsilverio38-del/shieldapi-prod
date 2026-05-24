const blockedTokens = new Map();

function getKey(token) {
  return String(token?.address || token?.tokenAddress || token?.symbol || token || '')
    .trim()
    .toLowerCase();
}

export function addBlockedToken(token, analysis = {}) {
  const key = getKey(token);
  if (!key) return null;

  const record = {
    key,
    token,
    analysis,
    blockedAt: new Date().toISOString(),
    blockingReasons: analysis.blockingReasons || [],
  };

  blockedTokens.set(key, record);
  return record;
}

export function listBlockedTokens() {
  return Array.from(blockedTokens.values());
}
