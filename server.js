import http from 'http';
import https from 'https';

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || '';

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-api-key',
    'Access-Control-Allow-Methods': 'GET, OPTIONS'
  });

  res.end(JSON.stringify(payload, null, 2));
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (apiRes) => {
        let data = '';

        apiRes.on('data', (chunk) => {
          data += chunk;
        });

        apiRes.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (error) {
            reject(new Error('Invalid response from external API'));
          }
        });
      })
      .on('error', (error) => {
        reject(error);
      });
  });
}

function isAuthorized(req, urlObj) {
  const keyFromQuery = urlObj.searchParams.get('key');
  const keyFromHeader = req.headers['x-api-key'];

  if (!API_KEY) {
    return true;
  }

  return keyFromQuery === API_KEY || keyFromHeader === API_KEY;
}

function getPairScore(pair) {
  const liquidity = Number(pair?.liquidity?.usd || 0);
  const volume24h = Number(pair?.volume?.h24 || 0);
  const volume1h = Number(pair?.volume?.h1 || 0);
  const buys24h = Number(pair?.txns?.h24?.buys || 0);
  const sells24h = Number(pair?.txns?.h24?.sells || 0);
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

  const validPairs = solanaPairs.filter((pair) => Number(pair?.liquidity?.usd || 0) > 0);

  if (validPairs.length === 0) {
    return null;
  }

  return validPairs.reduce((best, current) => {
    return getPairScore(current) > getPairScore(best) ? current : best;
  });
}

function analyzeRisk(pair) {
  const liquidity = Number(pair?.liquidity?.usd || 0);
  const volume24h = Number(pair?.volume?.h24 || 0);
  const priceChange5m = Number(pair?.priceChange?.m5 || 0);
  const priceChange1h = Number(pair?.priceChange?.h1 || 0);
  const priceChange24h = Number(pair?.priceChange?.h24 || 0);
  const txns24hBuys = Number(pair?.txns?.h24?.buys || 0);
  const txns24hSells = Number(pair?.txns?.h24?.sells || 0);
  const totalTxns24h = txns24hBuys + txns24hSells;

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

  return {
    status,
    riskScore,
    riskLevel,
    recommendation,
    reasons,
    price: pair?.priceUsd || null,
    liquidity: liquidity,
    volume24h: volume24h,
    txns24h: {
      buys: txns24hBuys,
      sells: txns24hSells,
      total: totalTxns24h
    },
    priceChange: {
      m5: priceChange5m,
      h1: priceChange1h,
      h24: priceChange24h
    },
    chain: 'solana',
    dex: pair?.dexId || null,
    pairAddress: pair?.pairAddress || null,
    tokenAddress: pair?.baseToken?.address || null,
    tokenName: pair?.baseToken?.name || null,
    tokenSymbol: pair?.baseToken?.symbol || null,
    dexUrl: pair?.url || null
  };
}

async function handleAnalyze(req, res, urlObj) {
  if (!isAuthorized(req, urlObj)) {
    return sendJson(res, 401, {
      status: 'UNAUTHORIZED',
      reason: 'API key missing or invalid'
    });
  }

  const token = urlObj.searchParams.get('token');
  const address = urlObj.searchParams.get('address');

  if (!token && !address) {
    return sendJson(res, 400, {
      status: 'ERROR',
      reason: 'Use /analyze?token=BONK or /analyze?address=MINT_ADDRESS'
    });
  }

  try {
    let apiUrl;

    if (address) {
      apiUrl = 'https://api.dexscreener.com/latest/dex/tokens/' + encodeURIComponent(address);
    } else {
      apiUrl = 'https://api.dexscreener.com/latest/dex/search?q=' + encodeURIComponent(token);
    }

    const parsed = await getJson(apiUrl);

    if (!parsed.pairs || parsed.pairs.length === 0) {
      return sendJson(res, 404, {
        status: 'ERROR',
        reason: 'Token not found.'
      });
    }

    const pair = getBestSolanaPair(parsed.pairs);

    if (!pair) {
      return sendJson(res, 403, {
        status: 'BLOCKED',
        reason: 'Token does not exist on Solana.'
      });
    }

    const result = analyzeRisk(pair);

    console.log('[ShieldAPI v4.2] ' + (token || address) + ' -> ' + result.status + ' | Risk: ' + result.riskScore);

    return sendJson(res, 200, result);
  } catch (error) {
    return sendJson(res, 500, {
      status: 'ERROR',
      reason: 'Internal error while analyzing token.',
      error: error.message
    });
  }
}

function handleDocs(res) {
  return sendJson(res, 200, {
    name: 'ShieldAPI',
    version: '4.2',
    description: 'Solana token risk analysis API for AI agents, trading bots and Web3 applications.',
    status: 'online',
    protected: Boolean(API_KEY),
    baseUrl: 'https://zucchini-caring-production.up.railway.app',
    authentication: {
      required: Boolean(API_KEY),
      methods: [
        'Query parameter: ?key=YOUR_API_KEY',
        'HTTP header: x-api-key: YOUR_API_KEY'
      ],
      example: '/analyze?token=BONK&key=YOUR_API_KEY'
    },
    routes: {
      health: {
        method: 'GET',
        path: '/health',
        description: 'Returns service status and version.'
      },
      docs: {
        method: 'GET',
        path: '/docs',
        description: 'Returns API documentation.'
      },
      analyzeByToken: {
        method: 'GET',
        path: '/analyze?token=BONK&key=YOUR_API_KEY',
        description: 'Searches a token by symbol/name and analyzes the best active Solana pair.'
      },
      analyzeByAddress: {
        method: 'GET',
        path: '/analyze?address=MINT_ADDRESS&key=YOUR_API_KEY',
        description: 'Analyzes a Solana token by mint address.'
      }
    },
    responseFields: {
      status: 'APPROVED, WARNING, BLOCKED, ERROR or UNAUTHORIZED',
      riskScore: 'Numeric risk score from 0 upward',
      riskLevel: 'LOW, MEDIUM, HIGH or CRITICAL',
      recommendation: 'Human-readable action suggestion',
      reasons: 'Array of detected risk reasons',
      price: 'Current token price in USD',
      liquidity: 'Pair liquidity in USD',
      volume24h: '24h trading volume in USD',
      txns24h: '24h buy/sell transaction count',
      priceChange: 'Price changes for 5m, 1h and 24h',
      chain: 'Always solana',
      dex: 'DEX identifier',
      pairAddress: 'DEX pair address',
      tokenAddress: 'Token mint address',
      tokenName: 'Token name',
      tokenSymbol: 'Token symbol',
      dexUrl: 'DexScreener URL'
    },
    exampleApprovedResponse: {
      status: 'APPROVED',
      riskScore: 0,
      riskLevel: 'LOW',
      recommendation: 'Token can be analyzed. Risk appears low.',
      reasons: ['No major risk signals detected on Solana.'],
      chain: 'solana'
    },
    disclaimer: 'ShieldAPI is a risk analysis tool. It does not execute trades, hold user funds, custody private keys or provide financial advice.'
  });
}

const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, 'http://localhost');

  if (req.method === 'OPTIONS') {
    return sendJson(res, 200, {
      status: 'OK'
    });
  }

  if (urlObj.pathname === '/health') {
    return sendJson(res, 200, {
      status: 'OK',
      service: 'ShieldAPI',
      version: '4.2',
      online: true,
      protected: Boolean(API_KEY)
    });
  }

  if (urlObj.pathname === '/docs') {
    return handleDocs(res);
  }

  if (urlObj.pathname === '/analyze') {
    return handleAnalyze(req, res, urlObj);
  }

  return sendJson(res, 200, {
    message: 'ShieldAPI v4.2 - Solana Risk Engine',
    docs: '/docs',
    health: '/health',
    routes: {
      analyzeByToken: '/analyze?token=BONK&key=YOUR_API_KEY',
      analyzeByAddress: '/analyze?address=MINT_ADDRESS&key=YOUR_API_KEY'
    }
  });
});

server.listen(PORT, () => {
  console.log('=================================');
  console.log(' SHIELD API v4.2 - PRODUCTION READY ');
  console.log(' PORT: ' + PORT);
  console.log(' PROTECTED: ' + Boolean(API_KEY));
  console.log('=================================');
});
