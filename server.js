import http from 'http';
import https from 'https';

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || '';

const VERSION = '4.3';
const SERVICE_NAME = 'ShieldAPI';

const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 60_000);
const CACHE_MAX_ITEMS = Number(process.env.CACHE_MAX_ITEMS || 50_000);
const EXTERNAL_TIMEOUT_MS = Number(process.env.EXTERNAL_TIMEOUT_MS || 3000);

const tokenCache = new Map();
const pendingAnalysis = new Map();

function nowIso() {
  return new Date().toISOString();
}

function startTimer() {
  return process.hrtime.bigint();
}

function responseTimeMs(startedAt) {
  const diffNs = process.hrtime.bigint() - startedAt;
  return Number((Number(diffNs) / 1_000_000).toFixed(2));
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-api-key, authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });

  res.end(JSON.stringify(payload, null, 2));
}

function normalizeAddress(value) {
  if (!value || typeof value !== 'string') {
    return '';
  }

  return value.trim();
}

function shortAddress(address) {
  if (!address || typeof address !== 'string') {
    return 'UNKNOWN';
  }

  if (address.length <= 12) {
    return address;
  }

  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function numberValue(value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return 0;
  }

  return parsed;
}

function safeString(value) {
  if (!value || typeof value !== 'string') {
    return null;
  }

  const cleaned = value.trim();
  return cleaned || null;
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { timeout: EXTERNAL_TIMEOUT_MS }, (apiRes) => {
      let data = '';

      apiRes.on('data', (chunk) => {
        data += chunk;
      });

      apiRes.on('end', () => {
        try {
          const parsed = JSON.parse(data);

          if (apiRes.statusCode < 200 || apiRes.statusCode >= 300) {
            const error = new Error(`External API HTTP ${apiRes.statusCode}`);
            error.statusCode = apiRes.statusCode;
            error.payload = parsed;
            reject(error);
            return;
          }

          resolve(parsed);
        } catch (error) {
          reject(new Error('Invalid response from external API'));
        }
      });
    });

    request.on('timeout', () => {
      request.destroy(new Error(`External API timeout after ${EXTERNAL_TIMEOUT_MS}ms`));
    });

    request.on('error', (error) => {
      reject(error);
    });
  });
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;

      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error('Request body too large'));
      }
    });

    req.on('end', () => {
      if (!body.trim()) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });

    req.on('error', reject);
  });
}

function getAuthKey(req, urlObj) {
  const keyFromQuery = urlObj.searchParams.get('key');
  const keyFromHeader = req.headers['x-api-key'];
  const authorization = req.headers.authorization || '';
  const bearer = authorization.replace(/^Bearer\s+/i, '');

  return keyFromQuery || keyFromHeader || bearer || '';
}

function isAuthorized(req, urlObj) {
  const providedKey = getAuthKey(req, urlObj);

  if (!API_KEY) {
    return true;
  }

  return providedKey === API_KEY;
}

function requireAuthorized(req, res, urlObj, startedAt) {
  if (isAuthorized(req, urlObj)) {
    return true;
  }

  sendJson(res, 401, {
    status: 'UNAUTHORIZED',
    reason: 'API key missing or invalid',
    responseTimeMs: responseTimeMs(startedAt)
  });

  return false;
}

function getCacheKey(input) {
  return normalizeAddress(input).toLowerCase();
}

function getCachedAnalysis(input) {
  const key = getCacheKey(input);

  if (!key) {
    return null;
  }

  const cached = tokenCache.get(key);

  if (!cached) {
    return null;
  }

  const ageMs = Date.now() - cached.cachedAtMs;

  return {
    ...cached,
    ageMs,
    isFresh: ageMs <= CACHE_TTL_MS
  };
}

function setCachedAnalysis(input, data) {
  const key = getCacheKey(input);

  if (!key) {
    return;
  }

  if (tokenCache.size >= CACHE_MAX_ITEMS && !tokenCache.has(key)) {
    const oldestKey = tokenCache.keys().next().value;

    if (oldestKey) {
      tokenCache.delete(oldestKey);
    }
  }

  tokenCache.set(key, {
    data,
    cachedAtMs: Date.now(),
    cachedAt: nowIso()
  });
}

function buildCacheMeta(cached, mode, startedAt) {
  return {
    mode,
    cacheHit: true,
    dataAgeSeconds: Math.round(cached.ageMs / 1000),
    responseTimeMs: responseTimeMs(startedAt)
  };
}

function getPairScore(pair) {
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

function getBestSolanaPair(pairs) {
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

function calculateOpportunityScore(pair, riskResult) {
  let score = 0;

  const liquidity = numberValue(pair?.liquidity?.usd);
  const volume24h = numberValue(pair?.volume?.h24);
  const txns24hBuys = numberValue(pair?.txns?.h24?.buys);
  const txns24hSells = numberValue(pair?.txns?.h24?.sells);
  const totalTxns24h = txns24hBuys + txns24hSells;
  const buySellRatio = txns24hSells > 0 ? txns24hBuys / txns24hSells : txns24hBuys > 0 ? 99 : 0;
  const priceChange5m = numberValue(pair?.priceChange?.m5);
  const priceChange1h = numberValue(pair?.priceChange?.h1);

  if (riskResult.status === 'APPROVED') {
    score += 25;
  }

  if (riskResult.riskLevel === 'LOW') {
    score += 20;
  }

  if (liquidity >= 250000) {
    score += 20;
  } else if (liquidity >= 100000) {
    score += 16;
  } else if (liquidity >= 50000) {
    score += 12;
  } else if (liquidity >= 25000) {
    score += 8;
  }

  if (volume24h >= 1000000) {
    score += 18;
  } else if (volume24h >= 250000) {
    score += 14;
  } else if (volume24h >= 100000) {
    score += 10;
  } else if (volume24h >= 50000) {
    score += 6;
  }

  if (totalTxns24h >= 10000) {
    score += 12;
  } else if (totalTxns24h >= 2000) {
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

function analyzeRisk(pair) {
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

async function analyzeToken(input) {
  const key = getCacheKey(input);

  if (pendingAnalysis.has(key)) {
    return pendingAnalysis.get(key);
  }

  const task = (async () => {
    let apiUrl;
    const looksLikeAddress = input.length >= 32;

    if (looksLikeAddress) {
      apiUrl = 'https://api.dexscreener.com/latest/dex/tokens/' + encodeURIComponent(input);
    } else {
      apiUrl = 'https://api.dexscreener.com/latest/dex/search?q=' + encodeURIComponent(input);
    }

    const parsed = await getJson(apiUrl);

    if (!parsed.pairs || parsed.pairs.length === 0) {
      const notFoundResult = {
        status: 'ERROR',
        riskLevel: 'UNKNOWN',
        riskScore: null,
        opportunityScore: 0,
        reason: 'Token not found.',
        reasons: ['Token not found.'],
        tokenAddress: looksLikeAddress ? input : null,
        tokenSymbol: looksLikeAddress ? shortAddress(input) : input,
        chain: 'solana',
        chainId: 'solana',
        analyzedAt: nowIso()
      };

      setCachedAnalysis(input, notFoundResult);
      return {
        httpStatus: 404,
        data: notFoundResult
      };
    }

    const pair = getBestSolanaPair(parsed.pairs);

    if (!pair) {
      const blockedResult = {
        status: 'BLOCKED',
        riskLevel: 'CRITICAL',
        riskScore: 100,
        opportunityScore: 0,
        reason: 'Token does not exist on Solana.',
        reasons: ['Token does not exist on Solana.'],
        tokenAddress: looksLikeAddress ? input : null,
        tokenSymbol: looksLikeAddress ? shortAddress(input) : input,
        chain: 'solana',
        chainId: 'solana',
        analyzedAt: nowIso()
      };

      setCachedAnalysis(input, blockedResult);
      return {
        httpStatus: 403,
        data: blockedResult
      };
    }

    const result = analyzeRisk(pair);

    setCachedAnalysis(input, result);

    if (result.tokenAddress) {
      setCachedAnalysis(result.tokenAddress, result);
    }

    if (result.tokenSymbol) {
      setCachedAnalysis(result.tokenSymbol, result);
    }

    return {
      httpStatus: 200,
      data: result
    };
  })();

  pendingAnalysis.set(key, task);

  try {
    return await task;
  } finally {
    pendingAnalysis.delete(key);
  }
}

async function handleAnalyze(req, res, urlObj) {
  const startedAt = startTimer();

  if (!requireAuthorized(req, res, urlObj, startedAt)) {
    return;
  }

  const token = normalizeAddress(urlObj.searchParams.get('token'));
  const address = normalizeAddress(urlObj.searchParams.get('address'));
  const refresh = String(urlObj.searchParams.get('refresh') || '').toLowerCase() === 'true';
  const input = address || token;

  if (!input) {
    return sendJson(res, 400, {
      status: 'ERROR',
      reason: 'Use /analyze?token=BONK or /analyze?address=MINT_ADDRESS',
      responseTimeMs: responseTimeMs(startedAt)
    });
  }

  try {
    const cached = getCachedAnalysis(input);

    if (cached && cached.isFresh && !refresh) {
      return sendJson(res, 200, {
        ...cached.data,
        mode: 'cache',
        cacheHit: true,
        dataAgeSeconds: Math.round(cached.ageMs / 1000),
        responseTimeMs: responseTimeMs(startedAt)
      });
    }

    const result = await analyzeToken(input);

    console.log(
      `[ShieldAPI v${VERSION}] ${input} -> ${result.data.status} | Risk: ${result.data.riskScore} | Opp: ${result.data.opportunityScore}`
    );

    return sendJson(res, result.httpStatus, {
      ...result.data,
      mode: 'deep',
      cacheHit: false,
      dataAgeSeconds: 0,
      responseTimeMs: responseTimeMs(startedAt)
    });
  } catch (error) {
    return sendJson(res, 500, {
      status: 'ERROR',
      reason: 'Internal error while analyzing token.',
      error: error.message,
      mode: 'deep',
      cacheHit: false,
      responseTimeMs: responseTimeMs(startedAt)
    });
  }
}

function handleAnalyzeFast(req, res, urlObj) {
  const startedAt = startTimer();

  if (!requireAuthorized(req, res, urlObj, startedAt)) {
    return;
  }

  const token = normalizeAddress(urlObj.searchParams.get('token'));
  const address = normalizeAddress(urlObj.searchParams.get('address'));
  const input = address || token;

  if (!input) {
    return sendJson(res, 400, {
      status: 'ERROR',
      reason: 'Use /analyze-fast?token=BONK or /analyze-fast?address=MINT_ADDRESS',
      responseTimeMs: responseTimeMs(startedAt)
    });
  }

  const cached = getCachedAnalysis(input);

  if (!cached) {
    return sendJson(res, 404, {
      status: 'UNKNOWN',
      riskLevel: 'UNKNOWN',
      riskScore: null,
      opportunityScore: 0,
      reason: 'Token not in cache yet. Call /analyze or /submit first.',
      tokenAddress: address || null,
      tokenSymbol: token || (address ? shortAddress(address) : null),
      mode: 'fast',
      cacheHit: false,
      dataAgeSeconds: null,
      responseTimeMs: responseTimeMs(startedAt)
    });
  }

  return sendJson(res, 200, {
    ...cached.data,
    ...buildCacheMeta(cached, 'fast', startedAt)
  });
}

async function handleSubmit(req, res, urlObj) {
  const startedAt = startTimer();

  if (!requireAuthorized(req, res, urlObj, startedAt)) {
    return;
  }

  try {
    const body = req.method === 'POST' ? await readRequestBody(req) : {};
    const token = normalizeAddress(body.token || urlObj.searchParams.get('token'));
    const address = normalizeAddress(body.address || urlObj.searchParams.get('address'));
    const input = address || token;

    if (!input) {
      return sendJson(res, 400, {
        status: 'ERROR',
        reason: 'Use /submit?token=BONK or /submit?address=MINT_ADDRESS',
        responseTimeMs: responseTimeMs(startedAt)
      });
    }

    analyzeToken(input).catch((error) => {
      console.log(`[ShieldAPI v${VERSION}] Background submit failed for ${input}: ${error.message}`);
    });

    return sendJson(res, 200, {
      status: 'QUEUED',
      reason: 'Token submitted for background analysis.',
      tokenAddress: address || null,
      tokenSymbol: token || (address ? shortAddress(address) : null),
      mode: 'submit',
      responseTimeMs: responseTimeMs(startedAt)
    });
  } catch (error) {
    return sendJson(res, 400, {
      status: 'ERROR',
      reason: error.message,
      responseTimeMs: responseTimeMs(startedAt)
    });
  }
}

function handleCacheStats(req, res, urlObj) {
  const startedAt = startTimer();

  if (!requireAuthorized(req, res, urlObj, startedAt)) {
    return;
  }

  return sendJson(res, 200, {
    status: 'OK',
    service: SERVICE_NAME,
    version: VERSION,
    cacheItems: tokenCache.size,
    cacheMaxItems: CACHE_MAX_ITEMS,
    cacheTtlMs: CACHE_TTL_MS,
    pendingAnalysis: pendingAnalysis.size,
    responseTimeMs: responseTimeMs(startedAt)
  });
}

function handleDocs(res) {
  return sendJson(res, 200, {
    name: SERVICE_NAME,
    version: VERSION,
    description: 'Solana token risk analysis API for AI agents, trading bots and Web3 applications.',
    status: 'online',
    protected: Boolean(API_KEY),
    baseUrl: 'https://zucchini-caring-production.up.railway.app',
    performanceTargets: {
      health: '<20ms typical',
      analyzeFastCacheHit: '<100ms target',
      analyzeDeep: 'Depends on DexScreener latency',
      submit: '<100ms target'
    },
    authentication: {
      required: Boolean(API_KEY),
      methods: [
        'Query parameter: ?key=YOUR_API_KEY',
        'HTTP header: x-api-key: YOUR_API_KEY',
        'HTTP header: Authorization: Bearer YOUR_API_KEY'
      ],
      example: '/analyze?token=BONK&key=YOUR_API_KEY'
    },
    routes: {
      health: {
        method: 'GET',
        path: '/health',
        description: 'Returns service status, version and cache stats.'
      },
      docs: {
        method: 'GET',
        path: '/docs',
        description: 'Returns API documentation.'
      },
      analyzeByToken: {
        method: 'GET',
        path: '/analyze?token=BONK&key=YOUR_API_KEY',
        description: 'Searches a token by symbol/name and analyzes the best active Solana pair. Uses cache if fresh.'
      },
      analyzeByAddress: {
        method: 'GET',
        path: '/analyze?address=MINT_ADDRESS&key=YOUR_API_KEY',
        description: 'Analyzes a Solana token by mint address. Uses cache if fresh.'
      },
      analyzeFast: {
        method: 'GET',
        path: '/analyze-fast?address=MINT_ADDRESS&key=YOUR_API_KEY',
        description: 'Cache-only fast response. Does not call DexScreener. Target under 100ms on cache hit.'
      },
      submit: {
        method: 'GET or POST',
        path: '/submit?address=MINT_ADDRESS&key=YOUR_API_KEY',
        description: 'Queues a token for background analysis and cache warming.'
      },
      cacheStats: {
        method: 'GET',
        path: '/cache/stats?key=YOUR_API_KEY',
        description: 'Returns cache statistics.'
      }
    },
    responseFields: {
      status: 'APPROVED, WARNING, BLOCKED, ERROR, UNKNOWN or UNAUTHORIZED',
      riskScore: 'Numeric risk score from 0 upward',
      riskLevel: 'LOW, MEDIUM, HIGH, CRITICAL or UNKNOWN',
      opportunityScore: '0-100 opportunity score with sell pressure penalty',
      recommendation: 'Human-readable action suggestion',
      reasons: 'Array of detected risk reasons',
      reason: 'Compact reason string',
      price: 'Current token price in USD',
      liquidity: 'Pair liquidity in USD',
      volume24h: '24h trading volume in USD',
      txns24h: '24h buy/sell transaction count',
      buySellRatio: '24h buys divided by sells',
      priceChange: 'Price changes for 5m, 1h, 6h and 24h',
      chain: 'Always solana',
      dex: 'DEX identifier',
      pairAddress: 'DEX pair address',
      tokenAddress: 'Token mint address',
      tokenName: 'Token name',
      tokenSymbol: 'Token symbol',
      dexUrl: 'DexScreener URL',
      cacheHit: 'true if response came from cache',
      dataAgeSeconds: 'Age of cached data in seconds',
      responseTimeMs: 'Server-side response time in milliseconds'
    },
    exampleApprovedResponse: {
      status: 'APPROVED',
      riskScore: 0,
      riskLevel: 'LOW',
      opportunityScore: 95,
      recommendation: 'Token can be analyzed. Risk appears low.',
      reasons: ['No major risk signals detected on Solana.'],
      chain: 'solana',
      cacheHit: true,
      responseTimeMs: 8.42
    },
    disclaimer: 'ShieldAPI is a risk analysis tool. It does not execute trades, hold user funds, custody private keys or provide financial advice.'
  });
}

const server = http.createServer(async (req, res) => {
  const startedAt = startTimer();
  const urlObj = new URL(req.url, 'http://localhost');

  if (req.method === 'OPTIONS') {
    return sendJson(res, 200, {
      status: 'OK',
      responseTimeMs: responseTimeMs(startedAt)
    });
  }

  if (urlObj.pathname === '/health') {
    return sendJson(res, 200, {
      status: 'OK',
      service: SERVICE_NAME,
      version: VERSION,
      online: true,
      protected: Boolean(API_KEY),
      cacheItems: tokenCache.size,
      pendingAnalysis: pendingAnalysis.size,
      uptimeSeconds: Math.round(process.uptime()),
      responseTimeMs: responseTimeMs(startedAt)
    });
  }

  if (urlObj.pathname === '/docs') {
    return handleDocs(res);
  }

  if (urlObj.pathname === '/analyze') {
    return handleAnalyze(req, res, urlObj);
  }

  if (urlObj.pathname === '/analyze-fast') {
    return handleAnalyzeFast(req, res, urlObj);
  }

  if (urlObj.pathname === '/submit') {
    return handleSubmit(req, res, urlObj);
  }

  if (urlObj.pathname === '/cache/stats') {
    return handleCacheStats(req, res, urlObj);
  }

  return sendJson(res, 200, {
    message: `ShieldAPI v${VERSION} - Solana Risk Engine + Fast Cache Layer`,
    docs: '/docs',
    health: '/health',
    routes: {
      analyzeByToken: '/analyze?token=BONK&key=YOUR_API_KEY',
      analyzeByAddress: '/analyze?address=MINT_ADDRESS&key=YOUR_API_KEY',
      analyzeFast: '/analyze-fast?address=MINT_ADDRESS&key=YOUR_API_KEY',
      submit: '/submit?address=MINT_ADDRESS&key=YOUR_API_KEY',
      cacheStats: '/cache/stats?key=YOUR_API_KEY'
    },
    responseTimeMs: responseTimeMs(startedAt)
  });
});

server.listen(PORT, () => {
  console.log('=================================');
  console.log(` SHIELD API v${VERSION} - FAST CACHE LAYER `);
  console.log(' PORT: ' + PORT);
  console.log(' PROTECTED: ' + Boolean(API_KEY));
  console.log(' CACHE TTL MS: ' + CACHE_TTL_MS);
  console.log(' CACHE MAX ITEMS: ' + CACHE_MAX_ITEMS);
  console.log(' EXTERNAL TIMEOUT MS: ' + EXTERNAL_TIMEOUT_MS);
  console.log('=================================');
});
