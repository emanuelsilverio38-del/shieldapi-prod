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
import { getQuotaWindow } from '../auth/quota.js';
import { getClientUsageSummary } from '../db/usageRepository.js';

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

export async function handleAnalyze(req, res, context = {}) {
  try {
    const tokenAddress = normalizeTokenAddress(
      getTokenAddressFromUrl(req)
    );

    if (!tokenAddress) {
      return sendJson(res, 400, {
        ok: false,
        error: 'missing_token_address',
        message: 'Use ?address=TOKEN_MINT',
      });
    }

    const analysis = await analyzeTokenSafety(tokenAddress, {
      mode: 'full',
    });

    setCachedAnalysis(tokenAddress, analysis);

    await saveAnalysisEverywhere(context.pool, tokenAddress, analysis, {
      memoryOnly: !context.pool,
    });

    return sendJson(res, 200, {
      ok: true,
      mode: 'full',
      cacheHit: false,
      dbHit: false,
      ...analysis,
    });
  } catch (error) {
    return sendJson(res, 500, {
      ok: false,
      error: 'analysis_failed',
      message: error.message,
    });
  }
}

export async function handleAnalyzeFast(req, res, context = {}) {
  try {
    const tokenAddress = normalizeTokenAddress(
      getTokenAddressFromUrl(req)
    );

    if (!tokenAddress) {
      return sendJson(res, 400, {
        ok: false,
        error: 'missing_token_address',
        message: 'Use ?address=TOKEN_MINT',
      });
    }

    const cached = getCachedAnalysis(tokenAddress);

    if (cached) {
      return sendJson(res, 200, {
        ok: true,
        mode: 'fast-memory',
        cacheHit: true,
        dbHit: false,
        ...cached,
      });
    }

    if (context.pool) {
      const dbCached = await getAnalysisFromDb(context.pool, tokenAddress);

      if (dbCached) {
        setCachedAnalysis(tokenAddress, dbCached);

        return sendJson(res, 200, {
          ok: true,
          mode: 'fast-db',
          cacheHit: true,
          dbHit: true,
          ...dbCached,
        });
      }
    }

    const analysis = await analyzeTokenSafety(tokenAddress, {
      mode: 'fast',
    });

    setCachedAnalysis(tokenAddress, analysis);

    await saveAnalysisEverywhere(context.pool, tokenAddress, analysis, {
      memoryOnly: !context.pool,
    });

    return sendJson(res, 200, {
      ok: true,
      mode: 'fast-live',
      cacheHit: false,
      dbHit: false,
      ...analysis,
    });
  } catch (error) {
    return sendJson(res, 500, {
      ok: false,
      error: 'fast_analysis_failed',
      message: error.message,
    });
  }
}

export async function handleSubmit(req, res, context = {}) {
  try {
    const body = await readRequestBody(req);
    const tokenAddress = normalizeTokenAddress(
      body.address || body.token || body.mint
    );

    if (!tokenAddress) {
      return sendJson(res, 400, {
        ok: false,
        error: 'missing_token_address',
        message: 'Body must include address, token or mint.',
      });
    }

    const analysis = body.analysis || await analyzeTokenSafety(tokenAddress, {
      mode: 'submitted',
    });

    setCachedAnalysis(tokenAddress, analysis);

    await saveAnalysisEverywhere(context.pool, tokenAddress, analysis, {
      memoryOnly: !context.pool,
    });

    return sendJson(res, 200, {
      ok: true,
      submitted: true,
      tokenAddress,
      analysis,
    });
  } catch (error) {
    return sendJson(res, 500, {
      ok: false,
      error: 'submit_failed',
      message: error.message,
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
    const client = context.client || null;

    if (!client) {
      return sendJson(res, 401, {
        ok: false,
        error: 'authentication_required',
        message: 'Valid API key is required.',
      });
    }

    const quotaWindow = getQuotaWindow(client.plan || 'free');
    const usage = await getClientUsageSummary(context.pool, client.id, {
      periodStart: quotaWindow.startsAt,
      periodEnd: quotaWindow.endsAt,
    });

    return sendJson(res, 200, {
      ok: true,
      client: {
        id: client.id,
        name: client.name,
        email: client.email,
        plan: client.plan,
        status: client.status,
        billingStatus: client.billing_status,
      },
      quotaWindow,
      usage,
    });
  } catch (error) {
    return sendJson(res, 500, {
      ok: false,
      error: 'usage_failed',
      message: error.message,
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