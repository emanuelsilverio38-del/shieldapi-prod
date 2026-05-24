# ShieldAPI

Security and intelligence API for Solana AI agents, trading bots and token scanners.

Antes do teu bot, agente ou scanner interagir com um token Solana, chama a ShieldAPI.

## What It Does

ShieldAPI returns a clear token decision:

- `APPROVED`
- `WARNING`
- `BLOCKED`

With risk scores, reasons, warnings, blocking reasons, market data, cache, usage, API keys and Stripe billing.

ShieldAPI is not financial advice and should not be marketed as a profit bot. It is a protection and decision layer for automated Solana systems.

## Current Runtime

- Node.js
- PostgreSQL
- Stripe
- Dexscreener-based initial analysis
- Memory and PostgreSQL cache
- API keys, plans, quota and rate limit
- Modular route dispatcher in progress

## Development

```powershell
npm install
npm start
npm test
```

## Important

Do not use `git add .` in this repository while old local artifacts are present. Add intended files explicitly.
