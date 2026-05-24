# Node.js Example

```js
const response = await fetch(
  'https://zucchini-caring-production.up.railway.app/analyze?token=BONK',
  {
    headers: {
      'x-api-key': process.env.SHIELD_API_KEY,
    },
  }
);

const data = await response.json();
console.log(data.status, data.riskScore);
```
