// src/routes/root.js

export function handleRoot(req, res, context = {}) {
  const startedAt = context.startedAt || Date.now();
  const version = context.version || '4.7';

  const responseTimeMs =
    typeof context.responseTimeMs === 'function'
      ? context.responseTimeMs(startedAt)
      : Math.round((Date.now() - startedAt) * 100) / 100;

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify(
      {
        message: `ShieldAPI v${version} - Stripe Billing Automation`,
        docs: '/docs',
        health: '/health',
        responseTimeMs
      },
      null,
      2
    )
  );

  return true;
}