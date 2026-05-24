# Analyze

`/analyze` performs a full token check.

```bash
curl "https://zucchini-caring-production.up.railway.app/analyze?address=TOKEN_MINT&key=YOUR_API_KEY"
```

Expected future decision values:

- `APPROVED`
- `WARNING`
- `BLOCKED`

The goal is to return:

- `riskScore`
- `securityScore`
- `opportunityScore`
- `reasons`
- `warnings`
- `blockingReasons`
- token and market data
- security checks
