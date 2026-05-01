import http from 'http';
import https from 'https';
import crypto from 'crypto';
import { Pool } from 'pg';

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || '';

const VERSION = '4.6';
const SERVICE_NAME = 'ShieldAPI';

const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 60_000);
const CACHE_MAX_ITEMS = Number(process.env.CACHE_MAX_ITEMS || 50_000);
const EXTERNAL_TIMEOUT_MS = Number(process.env.EXTERNAL_TIMEOUT_MS || 3000);

const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_ENABLED = String(process.env.RATE_LIMIT_ENABLED || 'true').toLowerCase() !== 'false';

const DATABASE_URL = process.env.DATABASE_URL || '';
const DATABASE_ENABLED = Boolean(DATABASE_URL);

const PLAN_CONFIG = {
  free: {
    name: 'Free',
    perMinute: 30,
    quota: 100,
    quotaPeriod: 'day'
  },
  starter: {
    name: 'Starter',
    perMinute: 120,
    quota: 10_000,
    quotaPeriod: 'month'
  },
  pro: {
    name: 'Pro',
    perMinute: 600,
    quota: 100_000,
    quotaPeriod: 'month'
  },
  advanced: {
    name: 'Advanced',
    perMinute: 1500,
    quota: 500_000,
    quotaPeriod: 'month'
  },
  enterprise: {
    name: 'Enterprise',
    perMinute: Number(process.env.ENTERPRISE_RATE_LIMIT_PER_MINUTE || 5000),
    quota: null,
    quotaPeriod: 'month'
  },
  master: {
    name: 'Master Admin',
    perMinute: Number(process.env.MASTER_RATE_LIMIT_PER_MINUTE || 5000),
    quota: null,
    quotaPeriod: 'month'
  }
};

const tokenCache = new Map();
const pendingAnalysis = new Map();
const rateLimitStore = new Map();

let dbPool = null;
let dbReady = false;
let dbLastError = null;

if (DATABASE_ENABLED) {
  dbPool = new Pool({
    connectionString: DATABASE_URL,
    max: Number(process.env.DB_POOL_MAX || 5),
    idleTimeoutMillis: Number(process.env.DB_IDLE_TIMEOUT_MS || 30_000),
    connectionTimeoutMillis: Number(process.env.DB_CONNECTION_TIMEOUT_MS || 5_000),
    ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
  });
}

const usageStats = {
  startedAt: nowIso(),
  totalRequests: 0,
  blockedByRateLimit: 0,
  blockedByQuota: 0,
  unauthorized: 0,
  byRoute: {},
  byStatus: {},
  byPlan: {}
};

function nowIso() {
  return new Date().toISOString();
}

function startTimer() {
  return process.hrtime.bigint();
}

function responseTimeMs(startedAt) {
  const diffNs = process.hrtime.bigint() - startedAt;
  return Number((Number(diffNs) / 1_000_000).toFixed(2));
}

function incrementCounter(object, key, amount = 1) {
  const safeKey = String(key || 'unknown');
  object[safeKey] = Number(object[safeKey] || 0) + amount;
}

function recordUsage(route, statusCode, options = {}) {
  if (options.countRequest !== false) {
    usageStats.totalRequests += 1;
    incrementCounter(usageStats.byRoute, route || 'unknown');
  }

  incrementCounter(usageStats.byStatus, statusCode || 'unknown');

  if (options.rateLimited) usageStats.blockedByRateLimit += 1;
  if (options.quotaLimited) usageStats.blockedByQuota += 1;
  if (options.unauthorized) usageStats.unauthorized += 1;
  if (options.plan) incrementCounter(usageStats.byPlan, options.plan);
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-api-key, authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });

  res.end(JSON.stringify(payload, null, 2));
}

function sendApiJson(res, statusCode, payload, context = {}) {
  const plan = context.auth?.plan || null;
  recordUsage(context.route || 'unknown', statusCode, {
    countRequest: false,
    plan,
    rateLimited: statusCode === 429 && payload?.status === 'RATE_LIMITED',
    quotaLimited: statusCode === 429 && payload?.status === 'QUOTA_LIMITED',
    unauthorized: statusCode === 401
  });

  if (context.auth && context.route) {
    recordClientUsageEvent(context.auth, context.route, statusCode, payload?.responseTimeMs, payload)
      .catch((error) => console.log('[USAGE] Failed to record usage event:', error.message));
  }

  return sendJson(res, statusCode, payload);
}

function normalizeAddress(value) {
  if (!value || typeof value !== 'string') return '';
  return value.trim();
}

function shortAddress(address) {
  if (!address || typeof address !== 'string') return 'UNKNOWN';
  if (address.length <= 12) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function numberValue(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function getRouteName(pathname) {
  if (pathname === '/health') return 'health';
  if (pathname === '/docs') return 'docs';
  if (pathname === '/analyze') return 'analyze';
  if (pathname === '/analyze-fast') return 'analyze_fast';
  if (pathname === '/submit') return 'submit';
  if (pathname === '/cache/stats') return 'cache_stats';
  if (pathname === '/usage') return 'usage';
  if (pathname === '/admin/clients/create') return 'admin_clients_create';
  if (pathname === '/admin/clients') return 'admin_clients_list';
  if (pathname === '/admin/clients/disable') return 'admin_clients_disable';
  if (pathname === '/admin/clients/usage') return 'admin_clients_usage';
  return 'unknown';
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown_ip';
}

function getAuthKey(req, urlObj) {
  const keyFromQuery = urlObj.searchParams.get('key');
  const keyFromHeader = req.headers['x-api-key'];
  const authorization = req.headers.authorization || '';
  const bearer = authorization.replace(/^Bearer\s+/i, '');
  return keyFromQuery || keyFromHeader || bearer || '';
}

function hashApiKey(apiKey) {
  return crypto.createHash('sha256').update(String(apiKey)).digest('hex');
}

function generateClientApiKey() {
  return `shield_live_${crypto.randomBytes(24).toString('hex')}`;
}

function normalizePlan(plan) {
  const normalized = String(plan || 'free').toLowerCase().trim();
  return PLAN_CONFIG[normalized] ? normalized : 'free';
}

function getPlanConfig(plan) {
  return PLAN_CONFIG[normalizePlan(plan)] || PLAN_CONFIG.free;
}

function getPeriodStart(period) {
  const now = new Date();

  if (period === 'day') {
    return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0));
  }

  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0));
}

function getPublicClient(client) {
  if (!client) return null;

  return {
    id: client.id,
    name: client.name,
    plan: client.plan,
    status: client.status,
    createdAt: client.created_at || client.createdAt || null,
    lastUsedAt: client.last_used_at || client.lastUsedAt || null,
    disabledAt: client.disabled_at || client.disabledAt || null
  };
}

async function initDatabase() {
  if (!dbPool) {
    dbReady = false;
    return false;
  }

  try {
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS token_analysis_cache (
        token_key TEXT PRIMARY KEY,
        token_address TEXT,
        token_symbol TEXT,
        status TEXT,
        risk_level TEXT,
        risk_score NUMERIC,
        opportunity_score NUMERIC,
        dex_url TEXT,
        payload JSONB NOT NULL,
        analyzed_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_token_analysis_cache_updated_at
      ON token_analysis_cache(updated_at DESC)
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_token_analysis_cache_status
      ON token_analysis_cache(status)
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS api_clients (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        plan TEXT NOT NULL DEFAULT 'free',
        api_key_hash TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        last_used_at TIMESTAMPTZ,
        disabled_at TIMESTAMPTZ
      )
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_clients_status
      ON api_clients(status)
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_clients_plan
      ON api_clients(plan)
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS api_usage_events (
        id BIGSERIAL PRIMARY KEY,
        client_id UUID,
        client_name TEXT,
        plan TEXT,
        route TEXT NOT NULL,
        status_code INTEGER,
        response_time_ms NUMERIC,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        metadata JSONB
      )
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_usage_client_created
      ON api_usage_events(client_id, created_at DESC)
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_usage_route_created
      ON api_usage_events(route, created_at DESC)
    `);

    dbReady = true;
    dbLastError = null;
    console.log('[DB] PostgreSQL cache + API clients ready.');
    return true;
  } catch (error) {
    dbReady = false;
    dbLastError = error.message;
    console.log('[DB] PostgreSQL init failed:', error.message);
    return false;
  }
}

async function findClientByApiKey(apiKey) {
  if (!dbPool || !dbReady || !apiKey) return null;

  const apiKeyHash = hashApiKey(apiKey);

  try {
    const result = await dbPool.query(
      `
      SELECT id, name, plan, status, created_at, updated_at, last_used_at, disabled_at
      FROM api_clients
      WHERE api_key_hash = $1
      LIMIT 1
      `,
      [apiKeyHash]
    );

    if (result.rows.length === 0) return null;
    return result.rows[0];
  } catch (error) {
    dbLastError = error.message;
    console.log('[CLIENTS] Failed to find client:', error.message);
    return null;
  }
}

async function authenticateRequest(req, urlObj, options = {}) {
  const providedKey = getAuthKey(req, urlObj);
  const master = Boolean(API_KEY && providedKey === API_KEY);

  if (master) {
    return {
      ok: true,
      type: 'master',
      master: true,
      client: null,
      clientId: null,
      clientName: 'MASTER',
      plan: 'master',
      planConfig: PLAN_CONFIG.master,
      identity: 'master'
    };
  }

  if (options.adminOnly) {
    return { ok: false, statusCode: 401, reason: 'Admin API key required' };
  }

  const client = await findClientByApiKey(providedKey);

  if (!client) {
    return { ok: false, statusCode: 401, reason: 'API key missing or invalid' };
  }

  if (client.status !== 'active') {
    return { ok: false, statusCode: 403, reason: 'API key is disabled' };
  }

  const plan = normalizePlan(client.plan);

  return {
    ok: true,
    type: 'client',
    master: false,
    client,
    clientId: client.id,
    clientName: client.name,
    plan,
    planConfig: getPlanConfig(plan),
    identity: `client:${client.id}`
  };
}

async function requireAuth(req, res, urlObj, startedAt, route, options = {}) {
  const auth = await authenticateRequest(req, urlObj, options);

  if (auth.ok) return auth;

  recordUsage(route, auth.statusCode || 401, { countRequest: false, unauthorized: true });

  sendJson(res, auth.statusCode || 401, {
    status: auth.statusCode === 403 ? 'FORBIDDEN' : 'UNAUTHORIZED',
    reason: auth.reason || 'API key missing or invalid',
    responseTimeMs: responseTimeMs(startedAt)
  });

  return null;
}

function shouldApplyRateLimit(route) {
  if (!RATE_LIMIT_ENABLED) return false;

  return route === 'analyze' ||
    route === 'analyze_fast' ||
    route === 'submit' ||
    route === 'cache_stats' ||
    route === 'usage' ||
    route.startsWith('admin_');
}

function cleanupRateLimitStore() {
  const now = Date.now();
  for (const [key, value] of rateLimitStore.entries()) {
    if (now >= value.resetAtMs + RATE_LIMIT_WINDOW_MS) rateLimitStore.delete(key);
  }
}

function checkRateLimit(auth, route) {
  const planConfig = auth?.planConfig || PLAN_CONFIG.free;
  const limitMax = Number(planConfig.perMinute || 30);

  if (!shouldApplyRateLimit(route)) {
    return { allowed: true, limit: limitMax, remaining: limitMax, resetAtMs: Date.now() + RATE_LIMIT_WINDOW_MS, retryAfterSeconds: 0 };
  }

  const identity = auth?.identity || 'anonymous';
  const key = `${identity}:${route}`;
  const now = Date.now();
  const existing = rateLimitStore.get(key);

  if (!existing || now >= existing.resetAtMs) {
    const fresh = { count: 1, resetAtMs: now + RATE_LIMIT_WINDOW_MS };
    rateLimitStore.set(key, fresh);
    return { allowed: true, identity, route, limit: limitMax, remaining: Math.max(0, limitMax - fresh.count), resetAtMs: fresh.resetAtMs, retryAfterSeconds: 0 };
  }

  existing.count += 1;
  rateLimitStore.set(key, existing);

  const retryAfterSeconds = Math.max(1, Math.ceil((existing.resetAtMs - now) / 1000));

  if (existing.count > limitMax) {
    return { allowed: false, identity, route, limit: limitMax, remaining: 0, resetAtMs: existing.resetAtMs, retryAfterSeconds };
  }

  return { allowed: true, identity, route, limit: limitMax, remaining: Math.max(0, limitMax - existing.count), resetAtMs: existing.resetAtMs, retryAfterSeconds: 0 };
}

function requireRateLimit(req, res, urlObj, startedAt, route, auth) {
  cleanupRateLimitStore();
  const limit = checkRateLimit(auth, route);

  if (limit.allowed) return true;

  recordUsage(route, 429, { rateLimited: true, countRequest: false, plan: auth?.plan });

  sendJson(res, 429, {
    status: 'RATE_LIMITED',
    reason: 'Too many requests',
    route,
    plan: auth?.plan || 'unknown',
    limit: limit.limit,
    remaining: limit.remaining,
    windowSeconds: Math.round(RATE_LIMIT_WINDOW_MS / 1000),
    retryAfterSeconds: limit.retryAfterSeconds,
    resetAt: new Date(limit.resetAtMs).toISOString(),
    responseTimeMs: responseTimeMs(startedAt)
  });

  return false;
}

async function getClientUsageCount(auth) {
  if (!dbPool || !dbReady || auth.master || !auth.clientId) return { count: 0, limit: null, period: 'none', allowed: true };

  const planConfig = auth.planConfig || getPlanConfig(auth.plan);
  if (!planConfig.quota) return { count: 0, limit: null, period: planConfig.quotaPeriod, allowed: true };

  const periodStart = getPeriodStart(planConfig.quotaPeriod);

  try {
    const result = await dbPool.query(
      `
      SELECT COUNT(*)::INT AS count
      FROM api_usage_events
      WHERE client_id = $1
        AND created_at >= $2
        AND status_code BETWEEN 200 AND 499
      `,
      [auth.clientId, periodStart]
    );

    const count = Number(result.rows[0]?.count || 0);
    return { count, limit: planConfig.quota, period: planConfig.quotaPeriod, allowed: count < planConfig.quota, periodStart };
  } catch (error) {
    dbLastError = error.message;
    return { count: 0, limit: planConfig.quota, period: planConfig.quotaPeriod, allowed: true, error: error.message };
  }
}

async function requireQuota(req, res, startedAt, route, auth) {
  const quota = await getClientUsageCount(auth);

  if (quota.allowed) return true;

  recordUsage(route, 429, { quotaLimited: true, countRequest: false, plan: auth?.plan });

  sendJson(res, 429, {
    status: 'QUOTA_LIMITED',
    reason: `Plan quota exceeded for current ${quota.period}`,
    route,
    plan: auth.plan,
    used: quota.count,
    limit: quota.limit,
    period: quota.period,
    responseTimeMs: responseTimeMs(startedAt)
  });

  return false;
}

async function recordClientUsageEvent(auth, route, statusCode, responseMs, payload) {
  if (!dbPool || !dbReady || !auth || auth.master) return;

  try {
    await dbPool.query(
      `
      INSERT INTO api_usage_events (
        client_id,
        client_name,
        plan,
        route,
        status_code,
        response_time_ms,
        metadata
      ) VALUES ($1,$2,$3,$4,$5,$6,$7)
      `,
      [
        auth.clientId,
        auth.clientName,
        auth.plan,
        route,
        Number(statusCode),
        Number(responseMs || 0),
        JSON.stringify({
          status: payload?.status || null,
          mode: payload?.mode || null,
          cacheHit: payload?.cacheHit ?? null,
          dbHit: payload?.dbHit ?? null
        })
      ]
    );

    await dbPool.query(
      `UPDATE api_clients SET last_used_at = NOW(), updated_at = NOW() WHERE id = $1`,
      [auth.clientId]
    );
  } catch (error) {
    dbLastError = error.message;
    console.log('[USAGE] Failed to record client usage:', error.message);
  }
}

function getCacheKey(input) {
  return normalizeAddress(input).toLowerCase();
}

function getCachedAnalysis(input) {
  const key = getCacheKey(input);
  if (!key) return null;

  const cached = tokenCache.get(key);
  if (!cached) return null;

  const ageMs = Date.now() - cached.cachedAtMs;
  return { ...cached, ageMs, isFresh: ageMs <= CACHE_TTL_MS };
}

function setCachedAnalysis(input, data) {
  const key = getCacheKey(input);
  if (!key) return;

  if (tokenCache.size >= CACHE_MAX_ITEMS && !tokenCache.has(key)) {
    const oldestKey = tokenCache.keys().next().value;
    if (oldestKey) tokenCache.delete(oldestKey);
  }

  tokenCache.set(key, { data, cachedAtMs: Date.now(), cachedAt: nowIso() });
}

function getAnalyzedAtFromPayload(payload) {
  const parsed = Date.parse(payload?.analyzedAt || payload?.updatedAt || new Date().toISOString());
  return Number.isFinite(parsed) ? new Date(parsed) : new Date();
}

async function saveAnalysisToDb(input, data) {
  if (!dbPool || !dbReady || !input || !data) return false;

  const tokenKey = getCacheKey(input);
  if (!tokenKey) return false;

  try {
    await dbPool.query(
      `
      INSERT INTO token_analysis_cache (
        token_key,
        token_address,
        token_symbol,
        status,
        risk_level,
        risk_score,
        opportunity_score,
        dex_url,
        payload,
        analyzed_at,
        updated_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
      ON CONFLICT (token_key)
      DO UPDATE SET
        token_address = EXCLUDED.token_address,
        token_symbol = EXCLUDED.token_symbol,
        status = EXCLUDED.status,
        risk_level = EXCLUDED.risk_level,
        risk_score = EXCLUDED.risk_score,
        opportunity_score = EXCLUDED.opportunity_score,
        dex_url = EXCLUDED.dex_url,
        payload = EXCLUDED.payload,
        analyzed_at = EXCLUDED.analyzed_at,
        updated_at = NOW()
      `,
      [
        tokenKey,
        data.tokenAddress || null,
        data.tokenSymbol || null,
        data.status || null,
        data.riskLevel || null,
        data.riskScore ?? null,
        data.opportunityScore ?? null,
        data.dexUrl || null,
        JSON.stringify(data),
        getAnalyzedAtFromPayload(data)
      ]
    );
    return true;
  } catch (error) {
    dbLastError = error.message;
    console.log(`[DB] Failed to save cache for ${input}: ${error.message}`);
    return false;
  }
}

async function getAnalysisFromDb(input) {
  if (!dbPool || !dbReady || !input) return null;

  const tokenKey = getCacheKey(input);
  if (!tokenKey) return null;

  try {
    const result = await dbPool.query(
      `
      SELECT payload, analyzed_at, updated_at
      FROM token_analysis_cache
      WHERE token_key = $1
      LIMIT 1
      `,
      [tokenKey]
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0];
    const payload = row.payload || null;
    if (!payload) return null;

    const updatedAtMs = new Date(row.updated_at || row.analyzed_at || Date.now()).getTime();
    const ageMs = Math.max(0, Date.now() - updatedAtMs);

    setCachedAnalysis(input, payload);
    if (payload.tokenAddress) setCachedAnalysis(payload.tokenAddress, payload);
    if (payload.tokenSymbol) setCachedAnalysis(payload.tokenSymbol, payload);

    return { data: payload, ageMs, analyzedAt: row.analyzed_at, updatedAt: row.updated_at };
  } catch (error) {
    dbLastError = error.message;
    console.log(`[DB] Failed to read cache for ${input}: ${error.message}`);
    return null;
  }
}

async function saveAnalysisEverywhere(input, data) {
  setCachedAnalysis(input, data);
  await saveAnalysisToDb(input, data);

  if (data?.tokenAddress && data.tokenAddress !== input) {
    setCachedAnalysis(data.tokenAddress, data);
    await saveAnalysisToDb(data.tokenAddress, data);
  }

  if (data?.tokenSymbol && data.tokenSymbol !== input) {
    setCachedAnalysis(data.tokenSymbol, data);
    await saveAnalysisToDb(data.tokenSymbol, data);
  }
}

function buildCacheMeta(cached, mode, startedAt) {
  return {
    mode,
    cacheHit: true,
    dbHit: false,
    dataAgeSeconds: Math.round(cached.ageMs / 1000),
    responseTimeMs: responseTimeMs(startedAt)
  };
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { timeout: EXTERNAL_TIMEOUT_MS }, (apiRes) => {
      let data = '';

      apiRes.on('data', (chunk) => { data += chunk; });

      apiRes.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (apiRes.statusCode < 200 || apiRes.statusCode >= 300) {
            const error = new Error(`External API HTTP ${apiRes.statusCode}`);
            error.statusCode = apiRes.statusCode;
            error.payload = parsed;
            reject(error);
            return;
          }
          resolve(parsed);
        } catch {
          reject(new Error('Invalid response from external API'));
        }
      });
    });

    request.on('timeout', () => request.destroy(new Error(`External API timeout after ${EXTERNAL_TIMEOUT_MS}ms`)));
    request.on('error', reject);
  });
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error('Request body too large'));
      }
    });

    req.on('end', () => {
      if (!body.trim()) { resolve({}); return; }
      try { resolve(JSON.parse(body)); } catch { reject(new Error('Invalid JSON body')); }
    });

    req.on('error', reject);
  });
}

function getPairScore(pair) {
  const liquidity = numberValue(pair?.liquidity?.usd);
  const volume24h = numberValue(pair?.volume?.h24);
  const volume1h = numberValue(pair?.volume?.h1);
  const buys24h = numberValue(pair?.txns?.h24?.buys);
  const sells24h = numberValue(pair?.txns?.h24?.sells);
  const totalTxns24h = buys24h + sells24h;

  let score = 0;
  score += Math.log10(liquidity + 1) * 25;
  score += Math.log10(volume24h + 1) * 30;
  score += Math.log10(volume1h + 1) * 20;
  score += Math.min(totalTxns24h, 2000) * 0.05;

  if (liquidity > 100000 && volume24h < 100 && totalTxns24h < 10) score -= 80;
  if (liquidity > 1000000 && volume24h < 1000 && totalTxns24h < 20) score -= 100;

  return score;
}

function getBestSolanaPair(pairs) {
  if (!Array.isArray(pairs)) return null;

  const solanaPairs = pairs.filter((pair) => pair.chainId === 'solana');
  if (solanaPairs.length === 0) return null;

  const validPairs = solanaPairs.filter((pair) => numberValue(pair?.liquidity?.usd) > 0);
  if (validPairs.length === 0) return null;

  return validPairs.reduce((best, current) => getPairScore(current) > getPairScore(best) ? current : best);
}

function calculateOpportunityScore(pair, riskResult) {
  let score = 0;

  const liquidity = numberValue(pair?.liquidity?.usd);
  const volume24h = numberValue(pair?.volume?.h24);
  const buys24h = numberValue(pair?.txns?.h24?.buys);
  const sells24h = numberValue(pair?.txns?.h24?.sells);
  const totalTxns24h = buys24h + sells24h;
  const buySellRatio = sells24h > 0 ? buys24h / sells24h : buys24h > 0 ? 99 : 0;
  const priceChange5m = numberValue(pair?.priceChange?.m5);
  const priceChange1h = numberValue(pair?.priceChange?.h1);

  if (riskResult.status === 'APPROVED') score += 25;
  if (riskResult.riskLevel === 'LOW') score += 20;

  if (liquidity >= 250_000) score += 20;
  else if (liquidity >= 100_000) score += 16;
  else if (liquidity >= 50_000) score += 12;
  else if (liquidity >= 25_000) score += 8;

  if (volume24h >= 1_000_000) score += 18;
  else if (volume24h >= 250_000) score += 14;
  else if (volume24h >= 100_000) score += 10;
  else if (volume24h >= 50_000) score += 6;

  if (totalTxns24h >= 10_000) score += 12;
  else if (totalTxns24h >= 2_000) score += 10;
  else if (totalTxns24h >= 500) score += 6;

  if (buySellRatio >= 1.25) score += 12;
  else if (buySellRatio >= 1.05) score += 8;
  else if (buySellRatio >= 0.9) score += 3;

  if (priceChange5m > 0) score += 4;
  if (priceChange1h > 0) score += 4;

  if (buySellRatio < 0.15) score -= 60;
  else if (buySellRatio < 0.25) score -= 45;
  else if (buySellRatio < 0.5) score -= 30;
  else if (buySellRatio < 0.75) score -= 15;
  else if (buySellRatio < 0.9) score -= 8;

  if (priceChange5m <= -10) score -= 12;
  else if (priceChange5m <= -5) score -= 6;

  if (priceChange1h <= -20) score -= 12;
  else if (priceChange1h <= -10) score -= 6;

  score = Math.max(0, Math.min(score, 100));

  if (buySellRatio < 0.15) score = Math.min(score, 25);
  else if (buySellRatio < 0.25) score = Math.min(score, 35);
  else if (buySellRatio < 0.5) score = Math.min(score, 50);
  else if (buySellRatio < 0.75) score = Math.min(score, 65);

  if (riskResult.status === 'BLOCKED') score = Math.min(score, 40);

  return score;
}

function analyzeRisk(pair) {
  const liquidity = numberValue(pair?.liquidity?.usd);
  const volume24h = numberValue(pair?.volume?.h24);
  const priceChange5m = numberValue(pair?.priceChange?.m5);
  const priceChange1h = numberValue(pair?.priceChange?.h1);
  const priceChange24h = numberValue(pair?.priceChange?.h24);
  const txns24hBuys = numberValue(pair?.txns?.h24?.buys);
  const txns24hSells = numberValue(pair?.txns?.h24?.sells);
  const totalTxns24h = txns24hBuys + txns24hSells;
  const buySellRatio = txns24hSells > 0 ? txns24hBuys / txns24hSells : txns24hBuys > 0 ? 99 : 0;

  let riskScore = 0;
  let status = 'APPROVED';
  let riskLevel = 'LOW';
  let recommendation = 'Token can be analyzed. This is not financial advice.';
  const reasons = [];

  if (liquidity < 5000) { riskScore += 80; reasons.push('Critical liquidity below $5,000.'); }
  else if (liquidity < 20000) { riskScore += 40; reasons.push('Low liquidity below $20,000.'); }
  else if (liquidity < 100000) { riskScore += 20; reasons.push('Moderate liquidity below $100,000.'); }

  if (!pair?.liquidity?.locked && liquidity < 100000) { riskScore += 20; reasons.push('Liquidity is not marked as locked and is below $100,000.'); }
  if (volume24h < 1000 && liquidity < 100000) { riskScore += 20; reasons.push('Very low 24h volume relative to liquidity.'); }
  if (totalTxns24h < 20 && liquidity < 100000) { riskScore += 15; reasons.push('Very low number of transactions in the last 24h.'); }

  if (txns24hSells > 0 && buySellRatio < 0.25) { riskScore += 30; reasons.push('Extreme sell pressure detected.'); }
  else if (txns24hSells > 0 && buySellRatio < 0.5) { riskScore += 20; reasons.push('High sell pressure detected.'); }
  else if (txns24hSells > 0 && buySellRatio < 0.75) { riskScore += 10; reasons.push('Sell pressure above normal.'); }

  if (priceChange24h <= -40) { riskScore += 25; reasons.push('Strong price drop in the last 24h.'); }
  if (priceChange1h <= -25) { riskScore += 20; reasons.push('Strong price drop in the last hour.'); }
  if (priceChange5m <= -15) { riskScore += 15; reasons.push('Strong price drop in the last 5 minutes.'); }

  if (riskScore >= 70) {
    status = 'BLOCKED'; riskLevel = 'CRITICAL'; recommendation = 'Block this token. Risk is very high.';
  } else if (riskScore >= 40) {
    status = 'BLOCKED'; riskLevel = 'HIGH'; recommendation = 'Block or manually review this token. Risk is high.';
  } else if (riskScore >= 20) {
    status = 'WARNING'; riskLevel = 'MEDIUM'; recommendation = 'Proceed with caution. The token can be analyzed, but risk exists.';
  } else {
    status = 'APPROVED'; riskLevel = 'LOW'; recommendation = 'Token can be analyzed. Risk appears low.';
  }

  if (reasons.length === 0) reasons.push('No major risk signals detected on Solana.');

  const baseResult = {
    status,
    riskScore,
    riskLevel,
    recommendation,
    reasons,
    reason: reasons.join(' / '),
    price: pair?.priceUsd || null,
    liquidity,
    volume24h,
    volume6h: numberValue(pair?.volume?.h6),
    volume1h: numberValue(pair?.volume?.h1),
    volume5m: numberValue(pair?.volume?.m5),
    txns24h: { buys: txns24hBuys, sells: txns24hSells, total: totalTxns24h },
    txns1h: {
      buys: numberValue(pair?.txns?.h1?.buys),
      sells: numberValue(pair?.txns?.h1?.sells),
      total: numberValue(pair?.txns?.h1?.buys) + numberValue(pair?.txns?.h1?.sells)
    },
    txns5m: {
      buys: numberValue(pair?.txns?.m5?.buys),
      sells: numberValue(pair?.txns?.m5?.sells),
      total: numberValue(pair?.txns?.m5?.buys) + numberValue(pair?.txns?.m5?.sells)
    },
    buySellRatio: Number(buySellRatio.toFixed(4)),
    priceChange: {
      m5: priceChange5m,
      h1: priceChange1h,
      h6: numberValue(pair?.priceChange?.h6),
      h24: priceChange24h
    },
    chain: 'solana',
    chainId: 'solana',
    dex: pair?.dexId || null,
    pairAddress: pair?.pairAddress || null,
    tokenAddress: pair?.baseToken?.address || null,
    tokenName: pair?.baseToken?.name || null,
    tokenSymbol: pair?.baseToken?.symbol || null,
    quoteTokenAddress: pair?.quoteToken?.address || null,
    quoteTokenSymbol: pair?.quoteToken?.symbol || null,
    fdv: numberValue(pair?.fdv),
    marketCap: numberValue(pair?.marketCap),
    pairCreatedAt: pair?.pairCreatedAt || null,
    dexUrl: pair?.url || null,
    analyzedAt: nowIso()
  };

  return { ...baseResult, opportunityScore: calculateOpportunityScore(pair, baseResult) };
}

async function analyzeToken(input) {
  const key = getCacheKey(input);
  if (pendingAnalysis.has(key)) return pendingAnalysis.get(key);

  const task = (async () => {
    const looksLikeAddress = input.length >= 32;
    const apiUrl = looksLikeAddress
      ? 'https://api.dexscreener.com/latest/dex/tokens/' + encodeURIComponent(input)
      : 'https://api.dexscreener.com/latest/dex/search?q=' + encodeURIComponent(input);

    const parsed = await getJson(apiUrl);

    if (!parsed.pairs || parsed.pairs.length === 0) {
      const notFoundResult = {
        status: 'ERROR', riskLevel: 'UNKNOWN', riskScore: null, opportunityScore: 0,
        reason: 'Token not found.', reasons: ['Token not found.'],
        tokenAddress: looksLikeAddress ? input : null,
        tokenSymbol: looksLikeAddress ? shortAddress(input) : input,
        chain: 'solana', chainId: 'solana', analyzedAt: nowIso()
      };
      await saveAnalysisEverywhere(input, notFoundResult);
      return { httpStatus: 404, data: notFoundResult };
    }

    const pair = getBestSolanaPair(parsed.pairs);

    if (!pair) {
      const blockedResult = {
        status: 'BLOCKED', riskLevel: 'CRITICAL', riskScore: 100, opportunityScore: 0,
        reason: 'Token does not exist on Solana.', reasons: ['Token does not exist on Solana.'],
        tokenAddress: looksLikeAddress ? input : null,
        tokenSymbol: looksLikeAddress ? shortAddress(input) : input,
        chain: 'solana', chainId: 'solana', analyzedAt: nowIso()
      };
      await saveAnalysisEverywhere(input, blockedResult);
      return { httpStatus: 403, data: blockedResult };
    }

    const result = analyzeRisk(pair);
    await saveAnalysisEverywhere(input, result);
    return { httpStatus: 200, data: result };
  })();

  pendingAnalysis.set(key, task);
  try { return await task; } finally { pendingAnalysis.delete(key); }
}\n
async function handleAnalyze(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route);
  if (!auth) return;
  if (!requireRateLimit(req, res, urlObj, startedAt, route, auth)) return;
  if (!(await requireQuota(req, res, startedAt, route, auth))) return;

  const token = normalizeAddress(urlObj.searchParams.get('token'));
  const address = normalizeAddress(urlObj.searchParams.get('address'));
  const refresh = String(urlObj.searchParams.get('refresh') || '').toLowerCase() === 'true';
  const input = address || token;

  if (!input) {
    return sendApiJson(res, 400, { status: 'ERROR', reason: 'Use /analyze?token=BONK or /analyze?address=MINT_ADDRESS', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }

  try {
    const cached = getCachedAnalysis(input);
    if (cached && cached.isFresh && !refresh) {
      return sendApiJson(res, 200, { ...cached.data, mode: 'cache', cacheHit: true, dbHit: false, dataAgeSeconds: Math.round(cached.ageMs / 1000), responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
    }

    const dbCached = !refresh ? await getAnalysisFromDb(input) : null;
    if (dbCached && dbCached.ageMs <= CACHE_TTL_MS) {
      return sendApiJson(res, 200, { ...dbCached.data, mode: 'db-cache', cacheHit: true, dbHit: true, dataAgeSeconds: Math.round(dbCached.ageMs / 1000), responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
    }

    const result = await analyzeToken(input);
    console.log(`[ShieldAPI v${VERSION}] ${input} -> ${result.data.status} | Risk: ${result.data.riskScore} | Opp: ${result.data.opportunityScore}`);

    return sendApiJson(res, result.httpStatus, { ...result.data, mode: 'deep', cacheHit: false, dbHit: false, dataAgeSeconds: 0, responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  } catch (error) {
    return sendApiJson(res, 500, { status: 'ERROR', reason: 'Internal error while analyzing token.', error: error.message, mode: 'deep', cacheHit: false, dbHit: false, responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }
}

async function handleAnalyzeFast(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route);
  if (!auth) return;
  if (!requireRateLimit(req, res, urlObj, startedAt, route, auth)) return;
  if (!(await requireQuota(req, res, startedAt, route, auth))) return;

  const token = normalizeAddress(urlObj.searchParams.get('token'));
  const address = normalizeAddress(urlObj.searchParams.get('address'));
  const input = address || token;

  if (!input) {
    return sendApiJson(res, 400, { status: 'ERROR', reason: 'Use /analyze-fast?token=BONK or /analyze-fast?address=MINT_ADDRESS', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }

  const cached = getCachedAnalysis(input);
  if (cached) {
    return sendApiJson(res, 200, { ...cached.data, ...buildCacheMeta(cached, 'fast', startedAt) }, { route, auth });
  }

  const dbCached = await getAnalysisFromDb(input);
  if (dbCached) {
    return sendApiJson(res, 200, { ...dbCached.data, mode: 'fast-db', cacheHit: true, dbHit: true, dataAgeSeconds: Math.round(dbCached.ageMs / 1000), responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }

  return sendApiJson(res, 404, {
    service: SERVICE_NAME, version: VERSION, status: 'UNKNOWN', riskLevel: 'UNKNOWN', riskScore: null, opportunityScore: 0,
    reason: 'Token not in cache or database yet. Call /analyze or /submit first.',
    tokenAddress: address || null,
    tokenSymbol: token || (address ? shortAddress(address) : null),
    mode: 'fast', cacheHit: false, dbHit: false, dataAgeSeconds: null,
    responseTimeMs: responseTimeMs(startedAt)
  }, { route, auth });
}

async function handleSubmit(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route);
  if (!auth) return;
  if (!requireRateLimit(req, res, urlObj, startedAt, route, auth)) return;
  if (!(await requireQuota(req, res, startedAt, route, auth))) return;

  try {
    const body = req.method === 'POST' ? await readRequestBody(req) : {};
    const token = normalizeAddress(body.token || urlObj.searchParams.get('token'));
    const address = normalizeAddress(body.address || urlObj.searchParams.get('address'));
    const input = address || token;

    if (!input) {
      return sendApiJson(res, 400, { status: 'ERROR', reason: 'Use /submit?token=BONK or /submit?address=MINT_ADDRESS', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
    }

    analyzeToken(input).catch((error) => console.error(`[SUBMIT] Background analysis failed for ${input}:`, error.message));

    return sendApiJson(res, 200, { service: SERVICE_NAME, version: VERSION, status: 'QUEUED', reason: 'Token submitted for background analysis.', tokenAddress: address || null, tokenSymbol: token || (address ? shortAddress(address) : null), mode: 'submit', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  } catch (error) {
    return sendApiJson(res, 400, { status: 'ERROR', reason: error.message, responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }
}

async function handleCacheStats(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route);
  if (!auth) return;
  if (!requireRateLimit(req, res, urlObj, startedAt, route, auth)) return;

  return sendApiJson(res, 200, {
    service: SERVICE_NAME,
    version: VERSION,
    cacheItems: tokenCache.size,
    cacheMaxItems: CACHE_MAX_ITEMS,
    cacheTtlMs: CACHE_TTL_MS,
    pendingAnalysis: pendingAnalysis.size,
    database: { enabled: DATABASE_ENABLED, ready: dbReady, lastError: dbLastError },
    responseTimeMs: responseTimeMs(startedAt)
  }, { route, auth });
}

async function handleUsage(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route);
  if (!auth) return;
  if (!requireRateLimit(req, res, urlObj, startedAt, route, auth)) return;

  const quota = await getClientUsageCount(auth);

  return sendApiJson(res, 200, {
    status: 'OK', service: SERVICE_NAME, version: VERSION,
    client: auth.master ? { type: 'master', plan: 'master' } : { id: auth.clientId, name: auth.clientName, plan: auth.plan },
    quota: auth.master ? null : { used: quota.count, limit: quota.limit, period: quota.period, remaining: quota.limit === null ? null : Math.max(0, quota.limit - quota.count) },
    startedAt: usageStats.startedAt,
    uptimeSeconds: Math.round(process.uptime()),
    totalRequests: usageStats.totalRequests,
    blockedByRateLimit: usageStats.blockedByRateLimit,
    blockedByQuota: usageStats.blockedByQuota,
    unauthorized: usageStats.unauthorized,
    byRoute: usageStats.byRoute,
    byStatus: usageStats.byStatus,
    byPlan: usageStats.byPlan,
    rateLimit: { enabled: RATE_LIMIT_ENABLED, planLimitPerMinute: auth.planConfig.perMinute, windowSeconds: Math.round(RATE_LIMIT_WINDOW_MS / 1000), activeWindows: rateLimitStore.size },
    cache: { items: tokenCache.size, maxItems: CACHE_MAX_ITEMS, ttlMs: CACHE_TTL_MS, pendingAnalysis: pendingAnalysis.size },
    database: { enabled: DATABASE_ENABLED, ready: dbReady, lastError: dbLastError },
    responseTimeMs: responseTimeMs(startedAt)
  }, { route, auth });
}

async function handleAdminCreateClient(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route, { adminOnly: true });
  if (!auth) return;
  if (!dbPool || !dbReady) return sendApiJson(res, 503, { status: 'ERROR', reason: 'Database is not ready', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });

  try {
    const body = req.method === 'POST' ? await readRequestBody(req) : {};
    const name = String(body.name || urlObj.searchParams.get('name') || '').trim();
    const plan = normalizePlan(body.plan || urlObj.searchParams.get('plan') || 'free');

    if (!name) return sendApiJson(res, 400, { status: 'ERROR', reason: 'Client name is required', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });

    const clientId = crypto.randomUUID();
    const apiKey = generateClientApiKey();
    const apiKeyHash = hashApiKey(apiKey);

    await dbPool.query(
      `INSERT INTO api_clients (id, name, plan, api_key_hash, status) VALUES ($1,$2,$3,$4,'active')`,
      [clientId, name, plan, apiKeyHash]
    );

    return sendApiJson(res, 201, {
      status: 'OK',
      message: 'Client created. Save this API key now; it will not be shown again.',
      client: { id: clientId, name, plan, status: 'active', planConfig: getPlanConfig(plan) },
      apiKey,
      responseTimeMs: responseTimeMs(startedAt)
    }, { route, auth });
  } catch (error) {
    return sendApiJson(res, 500, { status: 'ERROR', reason: error.message, responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }
}

async function handleAdminListClients(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route, { adminOnly: true });
  if (!auth) return;
  if (!dbPool || !dbReady) return sendApiJson(res, 503, { status: 'ERROR', reason: 'Database is not ready', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });

  try {
    const result = await dbPool.query(
      `SELECT id, name, plan, status, created_at, updated_at, last_used_at, disabled_at FROM api_clients ORDER BY created_at DESC LIMIT 200`
    );

    return sendApiJson(res, 200, { status: 'OK', clients: result.rows.map(getPublicClient), responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  } catch (error) {
    return sendApiJson(res, 500, { status: 'ERROR', reason: error.message, responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }
}

async function handleAdminDisableClient(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route, { adminOnly: true });
  if (!auth) return;
  if (!dbPool || !dbReady) return sendApiJson(res, 503, { status: 'ERROR', reason: 'Database is not ready', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });

  try {
    const body = req.method === 'POST' ? await readRequestBody(req) : {};
    const clientId = String(body.clientId || urlObj.searchParams.get('clientId') || '').trim();

    if (!clientId) return sendApiJson(res, 400, { status: 'ERROR', reason: 'clientId is required', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });

    const result = await dbPool.query(
      `UPDATE api_clients SET status='disabled', disabled_at=NOW(), updated_at=NOW() WHERE id=$1 RETURNING id, name, plan, status, created_at, updated_at, last_used_at, disabled_at`,
      [clientId]
    );

    if (result.rows.length === 0) return sendApiJson(res, 404, { status: 'ERROR', reason: 'Client not found', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });

    return sendApiJson(res, 200, { status: 'OK', client: getPublicClient(result.rows[0]), responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  } catch (error) {
    return sendApiJson(res, 500, { status: 'ERROR', reason: error.message, responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }
}

async function handleAdminClientUsage(req, res, urlObj) {
  const startedAt = startTimer();
  const route = getRouteName(urlObj.pathname);
  const auth = await requireAuth(req, res, urlObj, startedAt, route, { adminOnly: true });
  if (!auth) return;
  if (!dbPool || !dbReady) return sendApiJson(res, 503, { status: 'ERROR', reason: 'Database is not ready', responseTimeMs: responseTimeMs(startedAt) }, { route, auth });

  try {
    const clientId = String(urlObj.searchParams.get('clientId') || '').trim();
    const params = [];
    let where = `created_at >= NOW() - INTERVAL '30 days'`;

    if (clientId) {
      params.push(clientId);
      where += ` AND client_id = $1`;
    }

    const result = await dbPool.query(
      `
      SELECT client_id, client_name, plan, route, COUNT(*)::INT AS requests, AVG(response_time_ms)::NUMERIC(10,2) AS avg_response_ms
      FROM api_usage_events
      WHERE ${where}
      GROUP BY client_id, client_name, plan, route
      ORDER BY requests DESC
      LIMIT 200
      `,
      params
    );

    return sendApiJson(res, 200, { status: 'OK', window: '30d', rows: result.rows, responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  } catch (error) {
    return sendApiJson(res, 500, { status: 'ERROR', reason: error.message, responseTimeMs: responseTimeMs(startedAt) }, { route, auth });
  }
}

function handleDocs(res) {
  return sendJson(res, 200, {
    name: SERVICE_NAME,
    version: VERSION,
    description: 'Solana token risk analysis API for AI agents, trading bots and Web3 applications.',
    status: 'online',
    protected: Boolean(API_KEY),
    database: { enabled: DATABASE_ENABLED, ready: dbReady },
    plans: PLAN_CONFIG,
    authentication: {
      clientMethods: ['Query parameter: ?key=CLIENT_API_KEY', 'HTTP header: x-api-key: CLIENT_API_KEY', 'HTTP header: Authorization: Bearer CLIENT_API_KEY'],
      adminMethods: ['Use MASTER API_KEY for /admin endpoints']
    },
    routes: {
      health: '/health',
      docs: '/docs',
      analyzeByToken: '/analyze?token=BONK&key=YOUR_API_KEY',
      analyzeByAddress: '/analyze?address=MINT_ADDRESS&key=YOUR_API_KEY',
      analyzeFast: '/analyze-fast?address=MINT_ADDRESS&key=YOUR_API_KEY',
      submit: '/submit?address=MINT_ADDRESS&key=YOUR_API_KEY',
      cacheStats: '/cache/stats?key=YOUR_API_KEY',
      usage: '/usage?key=YOUR_API_KEY',
      adminCreateClient: 'POST /admin/clients/create?key=MASTER_API_KEY',
      adminListClients: 'GET /admin/clients?key=MASTER_API_KEY',
      adminDisableClient: 'POST /admin/clients/disable?key=MASTER_API_KEY',
      adminClientUsage: 'GET /admin/clients/usage?key=MASTER_API_KEY'
    },
    disclaimer: 'ShieldAPI is a risk analysis tool. It does not execute trades, hold user funds, custody private keys or provide financial advice.'
  });
}

const server = http.createServer(async (req, res) => {
  const startedAt = startTimer();
  const urlObj = new URL(req.url, 'http://localhost');
  const route = getRouteName(urlObj.pathname);

  recordUsage(route, 'received');

  if (req.method === 'OPTIONS') {
    return sendJson(res, 200, { status: 'OK', responseTimeMs: responseTimeMs(startedAt) });
  }

  if (urlObj.pathname === '/health') {
    return sendJson(res, 200, {
      status: 'OK', service: SERVICE_NAME, version: VERSION, online: true, protected: Boolean(API_KEY),
      cacheItems: tokenCache.size, pendingAnalysis: pendingAnalysis.size,
      rateLimit: { enabled: RATE_LIMIT_ENABLED, windowSeconds: Math.round(RATE_LIMIT_WINDOW_MS / 1000), activeWindows: rateLimitStore.size },
      database: { enabled: DATABASE_ENABLED, ready: dbReady, lastError: dbLastError },
      plans: Object.fromEntries(Object.entries(PLAN_CONFIG).map(([key, value]) => [key, { perMinute: value.perMinute, quota: value.quota, quotaPeriod: value.quotaPeriod }])),
      uptimeSeconds: Math.round(process.uptime()), responseTimeMs: responseTimeMs(startedAt)
    });
  }

  if (urlObj.pathname === '/docs') return handleDocs(res);
  if (urlObj.pathname === '/analyze') return handleAnalyze(req, res, urlObj);
  if (urlObj.pathname === '/analyze-fast') return handleAnalyzeFast(req, res, urlObj);
  if (urlObj.pathname === '/submit') return handleSubmit(req, res, urlObj);
  if (urlObj.pathname === '/cache/stats') return handleCacheStats(req, res, urlObj);
  if (urlObj.pathname === '/usage') return handleUsage(req, res, urlObj);
  if (urlObj.pathname === '/admin/clients/create') return handleAdminCreateClient(req, res, urlObj);
  if (urlObj.pathname === '/admin/clients') return handleAdminListClients(req, res, urlObj);
  if (urlObj.pathname === '/admin/clients/disable') return handleAdminDisableClient(req, res, urlObj);
  if (urlObj.pathname === '/admin/clients/usage') return handleAdminClientUsage(req, res, urlObj);

  return sendJson(res, 200, {
    message: `ShieldAPI v${VERSION} - Client API Keys + Plans`,
    docs: '/docs', health: '/health', responseTimeMs: responseTimeMs(startedAt)
  });
});

async function startServer() {
  await initDatabase();

  server.listen(PORT, () => {
    console.log('=================================');
    console.log(` SHIELD API v${VERSION} - CLIENT API KEYS + PLANS `);
    console.log(' PORT: ' + PORT);
    console.log(' PROTECTED: ' + Boolean(API_KEY));
    console.log(' CACHE TTL MS: ' + CACHE_TTL_MS);
    console.log(' DATABASE ENABLED: ' + DATABASE_ENABLED);
    console.log(' DATABASE READY: ' + dbReady);
    console.log(' PLANS: ' + Object.keys(PLAN_CONFIG).join(', '));
    console.log('=================================');
  });
}

process.on('SIGTERM', async () => {
  console.log('[SYSTEM] SIGTERM received. Closing server...');
  server.close(async () => {
    if (dbPool) await dbPool.end().catch(() => {});
    process.exit(0);
  });
});

startServer().catch((error) => {
  console.error('[FATAL] Failed to start server:', error);
  process.exit(1);
});
