export function detectWashTrading({
  liquidityUsd = 0,
  volume24h = 0,
  txns24h = 0,
  buySellRatio = 1,
} = {}) {
  const liquidity = Number(liquidityUsd || 0);
  const volume = Number(volume24h || 0);
  const txns = Number(txns24h || 0);
  const ratio = Number(buySellRatio || 1);
  const warnings = [];

  if (liquidity > 0 && volume / liquidity > 100 && txns < 100) {
    warnings.push('High volume/liquidity ratio with low transaction count');
  }

  if (ratio > 10 || ratio < 0.1) {
    warnings.push('Buy/sell ratio is highly imbalanced');
  }

  return {
    checked: true,
    suspected: warnings.length > 0,
    warnings,
  };
}
