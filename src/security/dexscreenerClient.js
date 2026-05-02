import { getJson } from '../utils/http.js';
import { getBestSolanaPair, analyzeDexRisk } from './dexRiskEngine.js';
import { nowIso } from '../utils/time.js';

export function looksLikeTokenAddress(input) {
  return typeof input === 'string' && input.trim().length >= 32;
}

export function shortAddress(address) {
  if (!address || typeof address !== 'string') {
    return 'UNKNOWN';
  }

  if (address.length <= 12) {
    return address;
  }

  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function buildDexscreenerUrl(input) {
  const cleanInput = String(input || '').trim();

  if (looksLikeTokenAddress(cleanInput)) {
    return `https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(cleanInput)}`;
  }

  return `https://api.dexscreener.com/latest/dex/search?q=${encodeURIComponent(cleanInput)}`;
}

export async function fetchDexscreenerPairs(input) {
  const apiUrl = buildDexscreenerUrl(input);
  const parsed = await getJson(apiUrl);

  return {
    apiUrl,
    pairs: Array.isArray(parsed?.pairs) ? parsed.pairs : []
  };
}

export function buildNotFoundResult(input) {
  const cleanInput = String(input || '').trim();
  const isAddress = looksLikeTokenAddress(cleanInput);

  return {
    status: 'ERROR',
    riskLevel: 'UNKNOWN',
    riskScore: null,
    opportunityScore: 0,
    reason: 'Token not found.',
    reasons: ['Token not found.'],
    tokenAddress: isAddress ? cleanInput : null,
    tokenSymbol: isAddress ? shortAddress(cleanInput) : cleanInput,
    chain: 'solana',
    chainId: 'solana',
    analyzedAt: nowIso()
  };
}

export function buildNotSolanaResult(input) {
  const cleanInput = String(input || '').trim();
  const isAddress = looksLikeTokenAddress(cleanInput);

  return {
    status: 'BLOCKED',
    riskLevel: 'CRITICAL',
    riskScore: 100,
    opportunityScore: 0,
    reason: 'Token does not exist on Solana.',
    reasons: ['Token does not exist on Solana.'],
    tokenAddress: isAddress ? cleanInput : null,
    tokenSymbol: isAddress ? shortAddress(cleanInput) : cleanInput,
    chain: 'solana',
    chainId: 'solana',
    analyzedAt: nowIso()
  };
}

export async function analyzeWithDexscreener(input) {
  const cleanInput = String(input || '').trim();

  const { pairs } = await fetchDexscreenerPairs(cleanInput);

  if (!pairs || pairs.length === 0) {
    return {
      httpStatus: 404,
      data: buildNotFoundResult(cleanInput)
    };
  }

  const pair = getBestSolanaPair(pairs);

  if (!pair) {
    return {
      httpStatus: 403,
      data: buildNotSolanaResult(cleanInput)
    };
  }

  const data = analyzeDexRisk(pair);

  return {
    httpStatus: 200,
    data,
    pair
  };
}