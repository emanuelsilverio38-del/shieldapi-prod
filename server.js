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

  res.end(JSON.stringify(payload));
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
            reject(new Error('Resposta invalida da API externa'));
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
  let recommendation = 'Pode ser analisado. Nao e uma recomendacao de compra.';
  const reasons = [];

  if (liquidity < 5000) {
    riskScore += 80;
    reasons.push('Liquidez critica inferior a $5.000.');
  } else if (liquidity < 20000) {
    riskScore += 40;
    reasons.push('Liquidez baixa inferior a $20.000.');
  } else if (liquidity < 100000) {
    riskScore += 20;
    reasons.push('Liquidez moderada inferior a $100.000.');
  }

  if (!pair?.liquidity?.locked && liquidity < 100000) {
    riskScore += 20;
    reasons.push('Liquidez nao marcada como bloqueada e inferior a $100.000.');
  }

  if (volume24h < 1000 && liquidity < 100000) {
    riskScore += 20;
    reasons.push('Volume 24h muito baixo para a liquidez existente.');
  }

  if (totalTxns24h < 20 && liquidity < 100000) {
    riskScore += 15;
    reasons.push('Poucas transacoes nas ultimas 24h.');
  }

  if (priceChange24h <= -40) {
    riskScore += 25;
    reasons.push('Queda forte nas ultimas 24h.');
  }

  if (priceChange1h <= -25) {
    riskScore += 20;
    reasons.push('Queda forte na ultima hora.');
  }

  if (priceChange5m <= -15) {
    riskScore += 15;
    reasons.push('Queda forte nos ultimos 5 minutos.');
  }

  if (riskScore >= 70) {
    status = 'BLOCKED';
    riskLevel = 'CRITICAL';
    recommendation = 'Bloquear. Risco muito elevado.';
  } else if (riskScore >= 40) {
    status = 'BLOCKED';
    riskLevel = 'HIGH';
    recommendation = 'Bloquear ou analisar manualmente. Risco elevado.';
  } else if (riskScore >= 20) {
    status = 'WARNING';
    riskLevel = 'MEDIUM';
    recommendation = 'Atencao. Pode ser analisado, mas com risco.';
  } else {
    status = 'APPROVED';
    riskLevel = 'LOW';
    recommendation = 'Pode ser analisado. Risco baixo.';
  }

  if (reasons.length === 0) {
    reasons.push('Sem sinais graves detetados na Solana.');
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
      reason: 'Usa /analyze?token=BONK ou /analyze?address=MINT_ADDRESS'
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
        reason: 'Token nao encontrado.'
      });
    }

    const pair = getBestSolanaPair(parsed.pairs);

    if (!pair) {
      return sendJson(res, 403, {
        status: 'BLOCKED',
        reason: 'Token nao existe na rede Solana.'
      });
    }

    const result = analyzeRisk(pair);

    console.log('[ShieldAPI v4.1] ' + (token || address) + ' -> ' + result.status + ' | Risk: ' + result.riskScore);

    return sendJson(res, 200, result);
  } catch (error) {
    return sendJson(res, 500, {
      status: 'ERROR',
      reason: 'Erro interno ao analisar token.',
      error: error.message
    });
  }
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
      version: '4.1',
      online: true,
      protected: Boolean(API_KEY)
    });
  }

  if (urlObj.pathname === '/analyze') {
    return handleAnalyze(req, res, urlObj);
  }

  return sendJson(res, 200, {
    message: 'ShieldAPI v4.1 - Solana Risk Engine',
    routes: {
      health: '/health',
      analyzeByToken: '/analyze?token=BONK',
      analyzeByAddress: '/analyze?address=MINT_ADDRESS'
    }
  });
});

server.listen(PORT, () => {
  console.log('=================================');
  console.log(' SHIELD API v4.1 - PRODUCTION READY ');
  console.log(' PORT: ' + PORT);
  console.log(' PROTECTED: ' + Boolean(API_KEY));
  console.log('=================================');
});
