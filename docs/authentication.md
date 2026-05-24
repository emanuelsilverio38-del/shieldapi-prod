# Authentication

ShieldAPI accepts API keys in one of three places:

- `x-api-key` header
- `Authorization: Bearer YOUR_API_KEY`
- `?key=YOUR_API_KEY` query parameter

Recommended:

```bash
curl \
  -H "x-api-key: YOUR_API_KEY" \
  "https://zucchini-caring-production.up.railway.app/usage"
```

API keys are stored as SHA-256 hashes in PostgreSQL.
