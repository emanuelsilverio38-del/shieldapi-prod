import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';

import { handleRoute } from '../src/routes/index.js';
import { generateClientApiKey, hashApiKey } from '../src/auth/apiKeys.js';

function createMockReq({
  method = 'GET',
  url = '/',
  headers = {},
  body = null,
} = {}) {
  const req = new Readable({
    read() {
      if (body === null || body === undefined) {
        this.push(null);
        return;
      }

      this.push(typeof body === 'string' ? body : JSON.stringify(body));
      this.push(null);
    },
  });

  req.method = method;
  req.url = url;
  req.headers = headers;
  req.socket = { remoteAddress: '127.0.0.1' };

  return req;
}

function createMockRes() {
  return {
    statusCode: null,
    headers: null,
    body: '',
    writeHead(statusCode, headers) {
      this.statusCode = statusCode;
      this.headers = headers;
    },
    end(chunk = '') {
      this.body += chunk;
    },
    json() {
      return JSON.parse(this.body);
    },
  };
}

function createContext(overrides = {}) {
  const startedAt = process.hrtime.bigint();

  return {
    version: '4.7',
    serviceName: 'ShieldAPI',
    startedAt,
    responseTimeMs(start) {
      const diffNs = process.hrtime.bigint() - start;
      return Number((Number(diffNs) / 1_000_000).toFixed(2));
    },
    dbReady: false,
    databaseEnabled: false,
    rateLimitEnabled: true,
    rateLimitWindowMs: 60_000,
    cacheStats: {
      items: 0,
      maxItems: 50_000,
      ttlMs: 60_000,
      pendingAnalysis: 0,
    },
    usageStats: {
      startedAt: new Date().toISOString(),
      totalRequests: 0,
      blockedByRateLimit: 0,
      blockedByQuota: 0,
      unauthorized: 0,
      byRoute: {},
      byStatus: {},
      byPlan: {},
    },
    ...overrides,
  };
}

function createUsagePool({ apiKey, clientId = '11111111-1111-4111-8111-111111111111' }) {
  const apiKeyHash = hashApiKey(apiKey);

  return {
    async query(sql, values = []) {
      if (sql.includes('FROM api_clients') && sql.includes('api_key_hash')) {
        if (values[0] !== apiKeyHash) return { rows: [] };

        return {
          rows: [{
            id: clientId,
            name: 'Test Client',
            email: 'client@example.com',
            plan: 'starter',
            status: 'active',
            billing_status: 'manual',
            current_period_end: null,
          }],
        };
      }

      if (sql.includes('COUNT(*)::int AS total_requests')) {
        return {
          rows: [{
            total_requests: 3,
            cache_hits: 1,
            db_hits: 1,
            avg_response_time_ms: 42,
          }],
        };
      }

      if (sql.includes('GROUP BY route')) {
        return {
          rows: [{
            route: 'analyze',
            requests: 3,
            cache_hits: 1,
            db_hits: 1,
            avg_response_time_ms: 42,
          }],
        };
      }

      return { rows: [] };
    },
  };
}

test('GET /usage authenticates a valid client key with mocked DB', async () => {
  const apiKey = generateClientApiKey();
  const req = createMockReq({
    method: 'GET',
    url: '/usage',
    headers: {
      'x-api-key': apiKey,
    },
  });
  const res = createMockRes();

  const handled = await handleRoute(req, res, createContext({
    pool: createUsagePool({ apiKey }),
    dbReady: true,
    databaseEnabled: true,
  }));

  assert.equal(handled, undefined);
  assert.equal(res.statusCode, 200);

  const payload = res.json();
  assert.equal(payload.status, 'OK');
  assert.equal(payload.client.plan, 'starter');
  assert.equal(payload.usage.totalRequests, 3);
});

test('GET /admin/clients without admin key is rejected', async () => {
  const req = createMockReq({
    method: 'GET',
    url: '/admin/clients',
  });
  const res = createMockRes();

  await handleRoute(req, res, createContext());

  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'authentication_required');
});

test('GET /analyze-fast without API key is rejected before external calls', async () => {
  const req = createMockReq({
    method: 'GET',
    url: '/analyze-fast?token=BONK',
  });
  const res = createMockRes();

  await handleRoute(req, res, createContext());

  assert.equal(res.statusCode, 401);
  assert.equal(res.json().status, 'UNAUTHORIZED');
});

test('GET /billing/create-checkout-session fails closed without Stripe config', async () => {
  const req = createMockReq({
    method: 'GET',
    url: '/billing/create-checkout-session?plan=starter',
  });
  const res = createMockRes();

  await handleRoute(req, res, createContext());

  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'checkout_session_failed');
});
