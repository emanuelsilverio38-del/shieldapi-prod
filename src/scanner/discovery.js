import { hasTokenBeenSeen, markTokenSeen } from './scannerState.js';

export function normalizeDiscoveredToken(token = {}) {
  const address = token.address || token.tokenAddress || token.mint || null;
  const symbol = token.symbol || token.tokenSymbol || null;

  return {
    address,
    symbol,
    name: token.name || token.tokenName || symbol || address || 'unknown',
    source: token.source || 'manual',
    discoveredAt: token.discoveredAt || new Date().toISOString(),
    raw: token,
  };
}

export function filterNewDiscoveredTokens(tokens = []) {
  const newTokens = [];

  for (const token of tokens) {
    const normalized = normalizeDiscoveredToken(token);
    const key = normalized.address || normalized.symbol;

    if (!key || hasTokenBeenSeen(key)) {
      continue;
    }

    markTokenSeen(key, {
      source: normalized.source,
    });
    newTokens.push(normalized);
  }

  return newTokens;
}
