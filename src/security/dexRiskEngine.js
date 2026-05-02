import { numberValue } from '../utils/numbers.js';
import { nowIso } from '../utils/time.js';

export function getPairScore(pair) {
  const liquidity = numberValue(pair?.liquidity?.usd);
  const volume24h = numberValue(pair?.volume?.h24);
  const volume1h = numberValue(pair?.volume?.h1);
  const buys24h = numberValue(pair?.txns?.h24?.buys);
  const sells24h = numberValue(pair?.txns?.h24?.sells);
  const totalTxns24h = buys24h + sells24h;

  let score = 0;

  score += Math.log10(liquidity + 1) * 25;
  score += Math.log10(volume24h + 1) * 30;
  score += Math.log10(volume1h + 1) * 20;
  score += Math.min(totalTxns24h, 2000) * 0.05;

  if (liquidity > 100000 && volume24h < 100 && totalTxns24h < 10) {
    score -= 80;
  }

  if (liquidity > 1000000 && volume24h < 1000 && totalTxns24h < 20) {
    score -= 100;
  }

  return score;
}

export function getBestSolanaPair(pairs) {
  if (!Array.isArray(pairs)) {
    return null;
  }

  const solanaPairs = pairs.filter((pair) => pair.chainId === 'solana');

  if (solanaPairs.length === 0) {
    return null;
  }

  const validPairs = solanaPairs.filter((pair) => numberValue(pair?.liquidity?.usd) > 0);

  if (validPairs.length === 0) {
    return null;
  }

  return validPairs.reduce((best, current) => {
    return getPairScore(current) > getPairScore(best) ? current : best;
  });
}

export function calculateOpportunityScore(pair, riskResult) {
  let score = 0;

  const liquidity = numberValue(pair?.liquidity?.usd);
  const volume24h = numberValue(pair?.volume?.h24);
  const buys24h = numberValue(pair?.txns?.h24?.buys);
  const sells24h = numberValue(pair?.txns?.h24?.sells);
  const totalTxns24h = buys24h + sells24h;
  const buySellRatio = sells24h > 0 ? buys24h / sells24h : buys24h > 0 ? 99 : 0;
  const priceChange5m = numberValue(pair?.priceChange?.m5);
  const priceChange1h = numberValue(pair?.priceChange?.h1);

  if (riskResult.status === 'APPROVED') {
    score += 25;
  }

  if (riskResult.riskLevel === 'LOW') {
    score += 20;
  }

  if (liquidity >= 250_000) {
    score += 20;
  } else if (liquidity >= 100_000) {
    score += 16;
  } else if (liquidity >= 50_000) {
    score += 12;
  } else if (liquidity >= 25_000) {
    score += 8;
  }

  if (volume24h >= 1_000_000) {
    score += 18;
  } else if (volume24h >= 250_000) {
    score += 14;
  } else if (volume24h >= 100_000) {
    score += 10;
  } else if (volume24h >= 50_000) {
    score += 6;
  }

  if (totalTxns24h >= 10_000) {
    score += 12;
  } else if (totalTxns24h >= 2_000) {
    score += 10;
  } else if (totalTxns24h >= 500) {
    score += 6;
  }

  if (buySellRatio >= 1.25) {
    score += 12;
  } else if (buySellRatio >= 1.05) {
    score += 8;
  } else if (buySellRatio >= 0.9) {
    score += 3;
  }

  if (priceChange5m > 0) {
    score += 4;
  }

  if (priceChange1h > 0) {
    score += 4;
  }

  if (buySellRatio < 0.15) {
    score -= 60;
  } else if (buySellRatio < 0.25) {
    score -= 45;
  } else if (buySellRatio < 0.5) {
    score -= 30;
  } else if (buySellRatio < 0.75) {
    score -= 15;
  } else if (buySellRatio < 0.9) {
    score -= 8;
  }

  if (priceChange5m <= -10) {
    score -= 12;
  } else if (priceChange5m <= -5) {
    score -= 6;
  }

  if (priceChange1h <= -20) {
    score -= 12;
  } else if (priceChange1h <= -10) {
    score -= 6;
  }

  score = Math.max(0, Math.min(score, 100));

  if (buySellRatio < 0.15) {
    score = Math.min(score, 25);
  } else if (buySellRatio < 0.25) {
    score = Math.min(score, 35);
  } else if (buySellRatio < 0.5) {
    score = Math.min(score, 50);
  } else if (buySellRatio < 0.75) {
    score = Math.min(score, 65);
  }

  if (riskResult.status === 'BLOCKED') {
    score = Math.min(score, 40);
  }

  return score;
}

export function analyzeDexRisk(pair) {
  const liquidity = numberValue(pair?.liquidity?.usd);
  const volume24h = numberValue(pair?.volume?.h24);
  const priceChange5m = numberValue(pair?.priceChange?.m5);
  const priceChange1h = numberValue(pair?.priceChange?.h1);
  const priceChange24h = numberValue(pair?.priceChange?.h24);
  const txns24hBuys = numberValue(pair?.txns?.h24?.buys);
  const txns24hSells = numberValue(pair?.txns?.h24?.sells);
  const totalTxns24h = txns24hBuys + txns24hSells;
  const buySellRatio = txns24hSells > 0 ? txns24hBuys / txns24hSells : txns24hBuys > 0 ? 99 : 0;

  let riskScore = 0;
  let status = 'APPROVED';
  let riskLevel = 'LOW';
  let recommendation = 'Token can be analyzed. This is not financial advice.';
  const reasons = [];

  if (liquidity < 5000) {
    riskScore += 80;
    reasons.push('Critical liquidity below $5,000.');
  } else if (liquidity < 20000) {
    riskScore += 40;
    reasons.push('Low liquidity below $20,000.');
  } else if (liquidity < 100000) {
    riskScore += 20;
    reasons.push('Moderate liquidity below $100,000.');
  }

  if (!pair?.liquidity?.locked && liquidity < 100000) {
    riskScore += 20;
    reasons.push('Liquidity is not marked as locked and is below $100,000.');
  }

  if (volume24h < 1000 && liquidity < 100000) {
    riskScore += 20;
    reasons.push('Very low 24h volume relative to liquidity.');
  }

  if (totalTxns24h < 20 && liquidity < 100000) {
    riskScore += 15;
    reasons.push('Very low number of transactions in the last 24h.');
  }

  if (txns24hSells > 0 && buySellRatio < 0.25) {
    riskScore += 30;
    reasons.push('Extreme sell pressure detected.');
  } else if (txns24hSells > 0 && buySellRatio < 0.5) {
    riskScore += 20;
    reasons.push('High sell pressure detected.');
  } else if (txns24hSells > 0 && buySellRatio < 0.75) {
    riskScore += 10;
    reasons.push('Sell pressure above normal.');
  }

  if (priceChange24h <= -40) {
    riskScore += 25;
    reasons.push('Strong price drop in the last 24h.');
  }

  if (priceChange1h <= -25) {
    riskScore += 20;
    reasons.push('Strong price drop in the last hour.');
  }

  if (priceChange5m <= -15) {
    riskScore += 15;
    reasons.push('Strong price drop in the last 5 minutes.');
  }

  if (riskScore >= 70) {
    status = 'BLOCKED';
    riskLevel = 'CRITICAL';
    recommendation = 'Block this token. Risk is very high.';
  } else if (riskScore >= 40) {
    status = 'BLOCKED';
    riskLevel = 'HIGH';
    recommendation = 'Block or manually review this token. Risk is high.';
  } else if (riskScore >= 20) {
    status = 'WARNING';
    riskLevel = 'MEDIUM';
    recommendation = 'Proceed with caution. The token can be analyzed, but risk exists.';
  } else {
    status = 'APPROVED';
    riskLevel = 'LOW';
    recommendation = 'Token can be analyzed. Risk appears low.';
  }

  if (reasons.length === 0) {
    reasons.push('No major risk signals detected on Solana.');
  }

  const baseResult = {
    status,
    riskScore,
    riskLevel,
    recommendation,
    reasons,
    reason: reasons.join(' / '),
    price: pair?.priceUsd || null,
    liquidity,
    volume24h,
    volume6h: numberValue(pair?.volume?.h6),
    volume1h: numberValue(pair?.volume?.h1),
    volume5m: numberValue(pair?.volume?.m5),
    txns24h: {
      buys: txns24hBuys,
      sells: txns24hSells,
      total: totalTxns24h
    },
    txns1h: {
      buys: numberValue(pair?.txns?.h1?.buys),
      sells: numberValue(pair?.txns?.h1?.sells),
      total: numberValue(pair?.txns?.h1?.buys) + numberValue(pair?.txns?.h1?.sells)
    },
    txns5m: {
      buys: numberValue(pair?.txns?.m5?.buys),
      sells: numberValue(pair?.txns?.m5?.sells),
      total: numberValue(pair?.txns?.m5?.buys) + numberValue(pair?.txns?.m5?.sells)
    },
    buySellRatio: Number(buySellRatio.toFixed(4)),
    priceChange: {
      m5: priceChange5m,
      h1: priceChange1h,
      h6: numberValue(pair?.priceChange?.h6),
      h24: priceChange24h
    },
    chain: 'solana',
    chainId: 'solana',
    dex: pair?.dexId || null,
    pairAddress: pair?.pairAddress || null,
    tokenAddress: pair?.baseToken?.address || null,
    tokenName: pair?.baseToken?.name || null,
    tokenSymbol: pair?.baseToken?.symbol || null,
    quoteTokenAddress: pair?.quoteToken?.address || null,
    quoteTokenSymbol: pair?.quoteToken?.symbol || null,
    fdv: numberValue(pair?.fdv),
    marketCap: numberValue(pair?.marketCap),
    pairCreatedAt: pair?.pairCreatedAt || null,
    dexUrl: pair?.url || null,
    analyzedAt: nowIso()
  };

  return {
    ...baseResult,
    opportunityScore: calculateOpportunityScore(pair, baseResult)
  };
}