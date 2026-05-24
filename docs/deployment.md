# Deployment

This deployment checklist is intentionally explicit because ShieldAPI handles billing, API keys and customer usage.

## Pre-Deploy

Run locally:

```powershell
npm.cmd run verify
```

Confirm:

- `git status --short` is clean or contains only intended changes
- no secrets are committed
- `.env.example` contains placeholders only
- critical routes fail closed without credentials

## Required Railway Variables

```text
NODE_ENV=production
SHIELD_API_VERSION=4.7
API_KEY=...
DATABASE_URL=...
STRIPE_SECRET_KEY=...
STRIPE_WEBHOOK_SECRET=...
STRIPE_PRICE_STARTER=...
STRIPE_PRICE_PRO=...
STRIPE_PRICE_ADVANCED=...
APP_URL=https://zucchini-caring-production.up.railway.app
DASHBOARD_SUCCESS_URL=https://zucchini-caring-production.up.railway.app/billing/success
DASHBOARD_CANCEL_URL=https://zucchini-caring-production.up.railway.app/billing/cancel
RUGCHECK_ENABLED=false
ONCHAIN_SECURITY_ENABLED=false
```

## Production Smoke Tests

```powershell
Invoke-RestMethod "https://zucchini-caring-production.up.railway.app/"
Invoke-RestMethod "https://zucchini-caring-production.up.railway.app/docs"
Invoke-RestMethod "https://zucchini-caring-production.up.railway.app/health"
Invoke-RestMethod "https://zucchini-caring-production.up.railway.app/cache/stats"
```

404 check:

```powershell
try {
  Invoke-WebRequest "https://zucchini-caring-production.up.railway.app/not-existing-deploy-test"
} catch {
  $_.Exception.Response.StatusCode.value__
}
```

Expected:

```text
404
```

## Auth Smoke Tests

Without API key:

```powershell
try {
  Invoke-WebRequest "https://zucchini-caring-production.up.railway.app/usage"
} catch {
  $_.Exception.Response.StatusCode.value__
}
```

Expected:

```text
401
```

With API key:

```powershell
Invoke-RestMethod `
  -Headers @{ "x-api-key" = "YOUR_API_KEY" } `
  "https://zucchini-caring-production.up.railway.app/usage"
```

Expected:

```text
status = OK
```

## Stripe Smoke Test

1. Create checkout session.
2. Pay with Stripe test card `4242 4242 4242 4242`.
3. Confirm `/billing/success` opens.
4. Confirm API key is shown once.
5. Confirm `/usage` works with the new key.
6. Confirm Stripe webhook receives `200`.

## External Security Checks

`RUGCHECK_ENABLED` and `ONCHAIN_SECURITY_ENABLED` default to `false`.

When disabled, `/analyze` must still work and report these checks as disabled or pending instead of failing.
