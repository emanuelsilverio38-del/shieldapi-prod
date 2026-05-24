# Python Example

```python
import os
import requests

response = requests.get(
    "https://zucchini-caring-production.up.railway.app/analyze",
    params={"token": "BONK"},
    headers={"x-api-key": os.environ["SHIELD_API_KEY"]},
    timeout=10,
)

data = response.json()
print(data.get("status"), data.get("riskScore"))
```
