export function analyzeLiquidity({
  liquidityUsd = 0,
  volume24h = 0,
  lockedOrBurned = null,
} = {}) {
  const liquidity = Number(liquidityUsd || 0);
  const volume = Number(volume24h || 0);
  const warnings = [];
  const blockingReasons = [];

  if (liquidity < 5_000) blockingReasons.push('Liquidity too low');
  else if (liquidity < 25_000) warnings.push('Liquidity is below recommended minimum');

  if (liquidity > 0 && volume / liquidity > 50) {
    warnings.push('Volume/liquidity ratio looks unusual');
  }

  return {
    checked: true,
    liquidityUsd: liquidity,
    volume24h: volume,
    lockedOrBurned,
    risk: blockingReasons.length ? 'HIGH' : warnings.length ? 'MEDIUM' : 'LOW',
    warnings,
    blockingReasons,
  };
}
