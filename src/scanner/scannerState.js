const seenTokens = new Map();

function normalizeTokenKey(token) {
  return String(token?.address || token?.tokenAddress || token?.symbol || token || '')
    .trim()
    .toLowerCase();
}

export function markTokenSeen(token, metadata = {}) {
  const key = normalizeTokenKey(token);

  if (!key) {
    return null;
  }

  const existing = seenTokens.get(key) || {};
  const now = new Date().toISOString();

  const record = {
    key,
    firstSeenAt: existing.firstSeenAt || now,
    lastSeenAt: now,
    count: Number(existing.count || 0) + 1,
    metadata: {
      ...(existing.metadata || {}),
      ...metadata,
    },
  };

  seenTokens.set(key, record);
  return record;
}

export function hasTokenBeenSeen(token) {
  const key = normalizeTokenKey(token);
  return key ? seenTokens.has(key) : false;
}

export function getScannerState() {
  return {
    seenCount: seenTokens.size,
    seenTokens: Array.from(seenTokens.values()),
  };
}

export function resetScannerState() {
  seenTokens.clear();
}
