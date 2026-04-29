import http from 'http';
import https from 'https';

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  if (req.url.startsWith('/analyze')) {
    const token = new URL(req.url, 'http://localhost').searchParams.get('token');
    console.log('[API v3.0 - SOLANA ONLY] Pedido para: ' + token);

    https.get('https://api.dexscreener.com/latest/dex/search?q=' + token, (apiRes) => {
      let data = '';
      apiRes.on('data', chunk => data += chunk);
      apiRes.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (!parsed.pairs || parsed.pairs.length === 0) {
            res.writeHead(404);
            return res.end(JSON.stringify({ status: 'ERROR', reason: 'Token nao encontrado na Solana' }));
          }
          const solanaPairs = parsed.pairs.filter(p => p.chainId === 'solana');
          if (solanaPairs.length === 0) {
            res.writeHead(403);
            return res.end(JSON.stringify({ status: 'BLOCKED', reason: 'Token nao existe na rede Solana.' }));
          }
          const pair = solanaPairs.reduce((a, b) => parseFloat(a.liquidity?.usd || 0) > parseFloat(b.liquidity?.usd || 0) ? a : b);
          const liq = parseFloat(pair.liquidity?.usd || 0);
          const price = let pair.priceUsd;

          let riskScore = 0;
          let status = 'APPROVED';
          let reason = 'Seguro na Solana.';

          if (liq < 5000) {
            riskScore += 80;
            status = 'BLOCKED';
            reason = 'Liquidez critica inferior a $5.000.';
          } else if (liq < 20000) {
            riskScore += 40;
            status = 'WARNING';
            reason = 'Liquidez baixa.';
          }

          if (!pair.liquidity?.locked && liq < 100000) {
            riskScore += 20;
            if (status !== 'BLOCKED') {
              status = 'BLOCKED';
              reason = 'RUG PULL RISK na Solana.';
            } else {
              reason += ' RUG RISK!';
            }
          }
          console.log('[API] Resultado: ' + status + ' - Risco: ' + riskScore);
          res.writeHead(200);
          res.end(JSON.stringify({ status, riskScore, reason, price: `${pair.priceUsd}`, liquidity: `${liq}`, chain: 'solana' }));
        } catch (e) {
          res.writeHead(500);
          res.end(JSON.stringify({ error: e.message }));
        }
      });
    }).on('error', (e) => {
      res.writeHead(0);
      res.end(JSON.stringify({ error: e.message }));
    });
  } else {
    res.writeHead(200);
    res.end(JSON.stringify({ message: 'ShieldAPI v3.0 - Escudo Inteligente' }));
  }
});

server.listen(process.env.PORT || 3000, () => {
  console.log('=================================');
  console.log(' SHIELD API v3.0 - PRODUCTION READY ');
  console.log('=================================');
});
