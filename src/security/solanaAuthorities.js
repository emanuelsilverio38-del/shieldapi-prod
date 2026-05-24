export function analyzeAuthorities(authorities = {}) {
  const mintAuthority = Boolean(authorities.mintAuthority);
  const freezeAuthority = Boolean(authorities.freezeAuthority);
  const warnings = [];
  const blockingReasons = [];

  if (mintAuthority) blockingReasons.push('Mint authority active');
  if (freezeAuthority) blockingReasons.push('Freeze authority active');

  return {
    checked: Boolean(authorities.checked),
    mintAuthority,
    freezeAuthority,
    risk: blockingReasons.length ? 'HIGH' : 'LOW',
    warnings,
    blockingReasons,
  };
}
