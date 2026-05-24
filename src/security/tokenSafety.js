import { analyzeWithDexscreener } from './dexscreenerClient.js';
import { env } from '../config/env.js';
import { checkRugcheck } from './rugcheckClient.js';
import { analyzeAuthorities } from './solanaAuthorities.js';
import { analyzeHolders } from './holdersAnalysis.js';
import { analyzeLiquidity } from './liquidityRisk.js';
import { analyzeCreator } from './creatorRisk.js';
import { analyzeMetadata } from './metadataRisk.js';
import { detectWashTrading } from './washTradingDetector.js';
import { buildDecision } from './riskScoring.js';

export async function analyzeTokenSafety(input, options = {}) {
  const cleanInput = String(input || '').trim();

  if (!cleanInput) {
    return {
      httpStatus: 400,
      data: {
        status: 'ERROR',
        riskLevel: 'UNKNOWN',
        riskScore: null,
        opportunityScore: 0,
        reason: 'Token input is required.',
        reasons: ['Token input is required.'],
        security: {
          dex: null,
          rugcheck: null,
          authorities: null,
          holders: null,
          creator: null
        }
      }
    };
  }

  const dexResult = await analyzeWithDexscreener(cleanInput);
  const dexData = dexResult.data || {};
  const rugcheck = await checkRugcheck(cleanInput, {
    enabled: options.rugcheckEnabled ?? env.RUGCHECK_ENABLED,
  });

  const authorities = analyzeAuthorities({
    checked: options.onchainSecurityEnabled ?? env.ONCHAIN_SECURITY_ENABLED,
  });
  const holders = analyzeHolders();
  const liquidity = analyzeLiquidity({
    liquidityUsd: dexData.liquidity,
    volume24h: dexData.volume24h,
  });
  const creator = analyzeCreator();
  const metadata = analyzeMetadata();
  const washTrading = detectWashTrading({
    liquidityUsd: dexData.liquidity,
    volume24h: dexData.volume24h,
    txns24h: dexData.txns24h?.total,
    buySellRatio: dexData.buySellRatio,
  });

  const warnings = [
    ...(dexData.status === 'WARNING' ? dexData.reasons || [] : []),
    ...(rugcheck.flags || []).map((flag) => `RugCheck flag: ${flag}`),
    ...(authorities.warnings || []),
    ...(holders.warnings || []),
    ...(liquidity.warnings || []),
    ...(creator.warnings || []),
    ...(metadata.warnings || []),
    ...(washTrading.warnings || []),
  ];

  const blockingReasons = [
    ...(dexData.status === 'BLOCKED' ? dexData.reasons || [] : []),
    ...(authorities.blockingReasons || []),
    ...(holders.blockingReasons || []),
    ...(liquidity.blockingReasons || []),
    ...(creator.blockingReasons || []),
    ...(metadata.blockingReasons || []),
  ];

  const decision = buildDecision({
    riskScore: dexData.riskScore ?? 0,
    opportunityScore: dexData.opportunityScore ?? 0,
    reasons: dexData.status === 'APPROVED' ? dexData.reasons || [] : [],
    warnings,
    blockingReasons,
  });

  const enrichedData = {
    ...dexData,
    ...decision,
    security: {
      dex: {
        checked: true,
        source: 'dexscreener',
        status: dexData.status,
        riskLevel: dexData.riskLevel,
        riskScore: dexData.riskScore,
        reasons: dexData.reasons || []
      },
      rugcheck,
      authorities,
      holders,
      liquidity,
      creator,
      metadata,
      washTrading
    },
    securityVersion: options.securityVersion || '4.8-dev'
  };

  return {
    ...dexResult,
    data: enrichedData
  };
}
