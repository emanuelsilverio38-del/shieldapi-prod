import { readRequestBody, sendJson } from '../utils/http.js';
import { analyzeTokenSafety } from '../security/tokenSafety.js';
import {
  getCachedAnalysis,
  setCachedAnalysis,
  getTokenCacheStats,
} from '../cache/tokenMemoryCache.js';
import {
  getAnalysisFromDb,
  saveAnalysisEverywhere,
} from '../db/tokenCacheRepository.js';
import { checkQuota, getQuotaWindow } from '../auth/quota.js';
import { authenticateRequest } from '../auth/apiKeys.js';
import { checkRateLimit, getRateLimitStats } from '../auth/rateLimit.js';
import {
  getClientUsageSummary,
  recordUsageEvent,
} from '../db/usageRepository.js';
import { validateAnalyzeInput } from '../validators/analyzeValidator.js';

function getTokenAddressFromUrl(req) {
  const url = new URL(req.url, 'http://localhost');
  return (
    url.searchParams.get('address') ||
    url.searchParams.get('token') ||
    url.searchParams.get('mint') ||
    null
  );
}

function normalizeTokenAddress(value) {
  return String(value || '').trim();
}

function getResponseTimer(context = {}) {
  const startedAt = context.startedAt || process.hrtime.bigint();
  const responseTimeMs =
    typeof context.responseTimeMs === 'function'
      ? context.responseTimeMs
      : () => 0;

  return { startedAt, responseTimeMs };
}

async function authenticateAndLimit(req, context = {}, route = 'unknown') {
  const url = new URL(req.url, 'http://localhost');
  const auth = await authenticateRequest(req, url, {
    pool: context.pool || context.dbPool || null,
    dbReady: context.dbReady,
  });

  if (!auth.ok) {
    return { ok: false, type: 'auth', auth };
  }

  const limit = checkRateLimit({
    client: auth.master ? { id: 'master', plan: 'master' } : auth.client,
    req,
    plan: auth.plan,
  });

  if (!limit.allowed) {
    return { ok: false, type: 'rate_limit', auth, limit };
  }

  if (!auth.master && ['analyze', 'analyze_fast', 'submit'].includes(route)) {
    const quota = await checkQuota({
      pool: context.pool || context.dbPool || null,
      client: auth.client,
    });

    if (!quota.allowed) {
      return { ok: false, type: 'quota', auth, quota };
    }
  }

  return { ok: true, auth, limit };
}

async function recordRouteUsage(context, auth, route, statusCode, responseTimeMsValue, payload = {}) {
  if (!context.pool || !context.dbReady || !auth || auth.master) return;

  await recordUsageEvent(context.pool, {
    clientId: auth.clientId,
    route,
    method: payload.method || null,
    statusCode,
    responseTimeMs: responseTimeMsValue,
    tokenAddress: payload.tokenAddress || null,
    cacheHit: Boolean(payload.cacheHit),
    dbHit: Boolean(payload.dbHit),
    metadata: {
      status: payload.status || null,
      mode: payload.mode || null,
    },
  }).catch(() => {});
}

function sendAuthFailure(res, failure, timer) {
  const { startedAt, responseTimeMs } = timer;

  if (failure.type === 'rate_limit') {
    return sendJson(res, 429, {
      status: 'RATE_LIMITED',
      reason: 'Too many requests',
      limit: failure.limit.limit,
      remaining: failure.limit.remaining,
      retryAfterSeconds: failure.limit.retryAfterSeconds,
      resetAt: failure.limit.resetAt,
      responseTimeMs: responseTimeMs(startedAt),
    });
  }

  if (failure.type === 'quota') {
    return sendJson(res, 429, {
      status: 'QUOTA_LIMITED',
      reason: `Plan quota exceeded for current ${failure.quota.period}`,
      plan: failure.quota.plan,
      used: failure.quota.used,
      limit: failure.quota.limit,
      remaining: failure.quota.remaining,
      period: failure.quota.period,
      responseTimeMs: responseTimeMs(startedAt),
    });
  }

  return sendJson(res, failure.auth.statusCode || 401, {
    status: failure.auth.statusCode === 403 ? 'FORBIDDEN' : 'UNAUTHORIZED',
    reason: failure.auth.reason || 'API key missing or invalid',
    responseTimeMs: responseTimeMs(startedAt),
  });
}

export async function handleAnalyze(req, res, context = {}) {
  const timer = getResponseTimer(context);

  try {
    const guard = await authenticateAndLimit(req, context, 'analyze');
    if (!guard.ok) return sendAuthFailure(res, guard, timer);

    const url = new URL(req.url, 'http://localhost');
    const tokenAddress = normalizeTokenAddress(getTokenAddressFromUrl(req));
    const validation = validateAnalyzeInput({
      address: url.searchParams.get('address') || url.searchParams.get('mint'),
      token: url.searchParams.get('token'),
      mode: 'full',
    });

    if (!validation.ok) {
      return sendJson(res, 400, {
        status: 'ERROR',
        reason: validation.message,
        error: validation.error,
        responseTimeMs: timer.responseTimeMs(timer.startedAt),
      });
    }

    const cached = getCachedAnalysis(validation.input);
    const refresh = String(url.searchParams.get('refresh') || '').toLowerCase() === 'true';

    if (cached && cached.isFresh && !refresh) {
      const payload = {
        ...cached.data,
        mode: 'cache',
        cacheHit: true,
        dbHit: false,
        dataAgeSeconds: Math.round(cached.ageMs / 1000),
        responseTimeMs: timer.responseTimeMs(timer.startedAt),
      };
      await recordRouteUsage(context, guard.auth, 'analyze', 200, payload.responseTimeMs, payload);
      return sendJson(res, 200, payload);
    }

    const dbCached = !refresh
      ? await getAnalysisFromDb(validation.input, {
          pool: context.pool || context.dbPool || null,
          ready: context.dbReady,
        })
      : null;

    if (dbCached) {
      const payload = {
        ...dbCached.data,
        mode: 'db-cache',
        cacheHit: true,
        dbHit: true,
        dataAgeSeconds: Math.round(dbCached.ageMs / 1000),
        responseTimeMs: timer.responseTimeMs(timer.startedAt),
      };
      await recordRouteUsage(context, guard.auth, 'analyze', 200, payload.responseTimeMs, payload);
      return sendJson(res, 200, payload);
    }

    const result = await analyzeTokenSafety(validation.input, {
      mode: 'full',
    });
    const analysis = result.data;

    setCachedAnalysis(validation.input, analysis);

    await saveAnalysisEverywhere(validation.input, analysis, {
      pool: context.pool || context.dbPool || null,
      ready: context.dbReady,
    });

    const payload = {
      ...analysis,
      mode: 'deep',
      cacheHit: false,
      dbHit: false,
      dataAgeSeconds: 0,
      responseTimeMs: timer.responseTimeMs(timer.startedAt),
    };
    await recordRouteUsage(context, guard.auth, 'analyze', result.httpStatus || 200, payload.responseTimeMs, payload);
    return sendJson(res, result.httpStatus || 200, payload);
  } catch (error) {
    return sendJson(res, 500, {
      status: 'ERROR',
      reason: 'Internal error while analyzing token.',
      error: error.message,
      mode: 'deep',
      cacheHit: false,
      dbHit: false,
      responseTimeMs: timer.responseTimeMs(timer.startedAt),
    });
  }
}

export async function handleAnalyzeFast(req, res, context = {}) {
  const timer = getResponseTimer(context);

  try {
    const guard = await authenticateAndLimit(req, context, 'analyze_fast');
    if (!guard.ok) return sendAuthFailure(res, guard, timer);

    const url = new URL(req.url, 'http://localhost');
    const tokenAddress = normalizeTokenAddress(getTokenAddressFromUrl(req));
    const validation = validateAnalyzeInput({
      address: url.searchParams.get('address') || url.searchParams.get('mint'),
      token: url.searchParams.get('token'),
      mode: 'fast',
    });

    if (!validation.ok) {
      return sendJson(res, 400, {
        status: 'ERROR',
        reason: validation.message,
        error: validation.error,
        responseTimeMs: timer.responseTimeMs(timer.startedAt),
      });
    }

    const cached = getCachedAnalysis(validation.input);

    if (cached) {
      const payload = {
        ...cached.data,
        mode: 'fast',
        cacheHit: true,
        dbHit: false,
        dataAgeSeconds: Math.round(cached.ageMs / 1000),
        responseTimeMs: timer.responseTimeMs(timer.startedAt),
      };
      await recordRouteUsage(context, guard.auth, 'analyze_fast', 200, payload.responseTimeMs, payload);
      return sendJson(res, 200, payload);
    }

    if (context.pool) {
      const dbCached = await getAnalysisFromDb(validation.input, {
        pool: context.pool || context.dbPool || null,
        ready: context.dbReady,
      });

      if (dbCached) {
        setCachedAnalysis(validation.input, dbCached.data);

        const payload = {
          ...dbCached.data,
          mode: 'fast-db',
          cacheHit: true,
          dbHit: true,
          dataAgeSeconds: Math.round(dbCached.ageMs / 1000),
          responseTimeMs: timer.responseTimeMs(timer.startedAt),
        };
        await recordRouteUsage(context, guard.auth, 'analyze_fast', 200, payload.responseTimeMs, payload);
        return sendJson(res, 200, payload);
      }
    }

    const payload = {
      service: context.serviceName || 'ShieldAPI',
      version: context.version || '4.7',
      status: 'UNKNOWN',
      riskLevel: 'UNKNOWN',
      riskScore: null,
      opportunityScore: 0,
      reason: 'Token not in cache or database yet. Call /analyze or /submit first.',
      tokenAddress: validation.inputType === 'address' ? validation.input : null,
      tokenSymbol: validation.inputType === 'symbol' ? validation.input : null,
      mode: 'fast',
      cacheHit: false,
      dbHit: false,
      dataAgeSeconds: null,
      responseTimeMs: timer.responseTimeMs(timer.startedAt),
    };
    await recordRouteUsage(context, guard.auth, 'analyze_fast', 404, payload.responseTimeMs, payload);
    return sendJson(res, 404, payload);
  } catch (error) {
    return sendJson(res, 500, {
      status: 'ERROR',
      reason: error.message,
      mode: 'fast',
      responseTimeMs: timer.responseTimeMs(timer.startedAt),
    });
  }
}

export async function handleSubmit(req, res, context = {}) {
  const timer = getResponseTimer(context);

  try {
    const guard = await authenticateAndLimit(req, context, 'submit');
    if (!guard.ok) return sendAuthFailure(res, guard, timer);

    const body = await readRequestBody(req);
    const validation = validateAnalyzeInput({
      address: body.address || body.mint,
      token: body.token,
      mode: 'submitted',
    });

    if (!validation.ok) {
      return sendJson(res, 400, {
        status: 'ERROR',
        reason: validation.message,
        error: validation.error,
        responseTimeMs: timer.responseTimeMs(timer.startedAt),
      });
    }

    const result = body.analysis
      ? { httpStatus: 200, data: body.analysis }
      : await analyzeTokenSafety(validation.input, { mode: 'submitted' });
    const analysis = result.data;

    setCachedAnalysis(validation.input, analysis);

    await saveAnalysisEverywhere(validation.input, analysis, {
      pool: context.pool || context.dbPool || null,
      ready: context.dbReady,
    });

    const payload = {
      service: context.serviceName || 'ShieldAPI',
      version: context.version || '4.7',
      status: 'QUEUED',
      reason: 'Token submitted for analysis/cache.',
      tokenAddress: validation.inputType === 'address' ? validation.input : analysis?.tokenAddress || null,
      tokenSymbol: validation.inputType === 'symbol' ? validation.input : analysis?.tokenSymbol || null,
      mode: 'submit',
      responseTimeMs: timer.responseTimeMs(timer.startedAt),
    };
    await recordRouteUsage(context, guard.auth, 'submit', result.httpStatus || 200, payload.responseTimeMs, payload);
    return sendJson(res, 200, payload);
  } catch (error) {
    return sendJson(res, 500, {
      status: 'ERROR',
      reason: error.message,
      responseTimeMs: timer.responseTimeMs(timer.startedAt),
    });
  }
}

export async function handleCacheStats(req, res) {
  return sendJson(res, 200, {
    ok: true,
    cache: getTokenCacheStats(),
  });
}

export async function handleUsage(req, res, context = {}) {
  try {
    const startedAt = context.startedAt || process.hrtime.bigint();
    const responseTimeMs =
      typeof context.responseTimeMs === 'function'
        ? context.responseTimeMs
        : () => 0;

    const url = new URL(req.url, 'http://localhost');
    const auth = await authenticateRequest(req, url, {
      pool: context.pool || context.dbPool || null,
      dbReady: context.dbReady,
    });

    if (!auth.ok) {
      return sendJson(res, auth.statusCode || 401, {
        status: auth.statusCode === 403 ? 'FORBIDDEN' : 'UNAUTHORIZED',
        reason: auth.reason || 'API key missing or invalid',
        responseTimeMs: responseTimeMs(startedAt),
      });
    }

    const rateLimit = checkRateLimit({
      client: auth.client,
      req,
      plan: auth.plan,
    });

    if (!rateLimit.allowed) {
      return sendJson(res, 429, {
        status: 'RATE_LIMITED',
        reason: 'Too many requests',
        route: 'usage',
        plan: auth.plan || 'unknown',
        limit: rateLimit.limit,
        remaining: rateLimit.remaining,
        retryAfterSeconds: rateLimit.retryAfterSeconds,
        resetAt: rateLimit.resetAt,
        responseTimeMs: responseTimeMs(startedAt),
      });
    }

    const quotaWindow = getQuotaWindow(auth.plan || 'free');
    const usage = auth.master
      ? null
      : await getClientUsageSummary(context.pool, auth.clientId, {
          periodStart: quotaWindow.startsAt,
          periodEnd: quotaWindow.endsAt,
        });

    const quota = auth.master
      ? null
      : {
          used: usage?.totalRequests ?? 0,
          limit: auth.planConfig?.quota ?? null,
          period: quotaWindow.period,
          remaining: auth.planConfig?.quota === null || auth.planConfig?.quota === undefined
            ? null
            : Math.max(0, Number(auth.planConfig.quota) - Number(usage?.totalRequests || 0)),
        };

    return sendJson(res, 200, {
      status: 'OK',
      service: context.serviceName || 'ShieldAPI',
      version: context.version || '4.7',
      client: auth.master
        ? { type: 'master', plan: 'master' }
        : {
            id: auth.clientId,
            name: auth.clientName,
            email: auth.client?.email || null,
            plan: auth.plan,
            status: auth.client?.status || null,
            billingStatus: auth.client?.billing_status || null,
          },
      quota,
      quotaWindow: auth.master ? null : quotaWindow,
      usage,
      startedAt: context.usageStats?.startedAt || null,
      uptimeSeconds: Math.round(process.uptime()),
      totalRequests: context.usageStats?.totalRequests ?? null,
      blockedByRateLimit: context.usageStats?.blockedByRateLimit ?? null,
      blockedByQuota: context.usageStats?.blockedByQuota ?? null,
      unauthorized: context.usageStats?.unauthorized ?? null,
      byRoute: context.usageStats?.byRoute || null,
      byStatus: context.usageStats?.byStatus || null,
      byPlan: context.usageStats?.byPlan || null,
      rateLimit: {
        enabled: context.rateLimitEnabled ?? true,
        planLimitPerMinute: auth.planConfig?.perMinute ?? rateLimit.limit,
        windowSeconds: Math.round((context.rateLimitWindowMs || 60_000) / 1000),
        activeWindows: getRateLimitStats().activeWindows,
      },
      cache: context.cacheStats || null,
      database: {
        enabled: context.databaseEnabled ?? Boolean(context.pool),
        ready: Boolean(context.dbReady),
        lastError: context.dbLastError || null,
      },
      responseTimeMs: responseTimeMs(startedAt),
    });
  } catch (error) {
    return sendJson(res, 500, {
      status: 'ERROR',
      reason: error.message,
    });
  }
}

export function isAnalyzeRoute(pathname) {
  return [
    '/analyze',
    '/analyze-fast',
    '/submit',
    '/cache/stats',
    '/usage',
  ].includes(pathname);
}
