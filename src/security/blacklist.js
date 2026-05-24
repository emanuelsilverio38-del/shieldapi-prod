const blockedTokens = new Set();
const blockedCreators = new Set();

export function isTokenBlacklisted(address) {
  return blockedTokens.has(String(address || '').trim());
}

export function isCreatorBlacklisted(address) {
  return blockedCreators.has(String(address || '').trim());
}

export function addBlockedToken(address) {
  if (address) blockedTokens.add(String(address).trim());
}

export function addBlockedCreator(address) {
  if (address) blockedCreators.add(String(address).trim());
}

export function getBlacklistStats() {
  return {
    blockedTokens: blockedTokens.size,
    blockedCreators: blockedCreators.size,
  };
}
