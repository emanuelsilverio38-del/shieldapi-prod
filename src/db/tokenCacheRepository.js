import { dbPool, dbReady } from './pool.js';
import { setCachedAnalysis } from '../cache/tokenMemoryCache.js';

function getCacheKey(input) {
  if (!input || typeof input !== 'string') {
    return '';
  }

  return input.trim().toLowerCase();
}

function getAnalyzedAtFromPayload(payload) {
  const parsed = Date.parse(payload?.analyzedAt || payload?.updatedAt || new Date().toISOString());

  if (!Number.isFinite(parsed)) {
    return new Date();
  }

  return new Date(parsed);
}

export async function saveAnalysisToDb(input, data, {
  pool = dbPool,
  ready = dbReady,
} = {}) {
  if (!pool || !ready || !input || !data) {
    return false;
  }

  const tokenKey = getCacheKey(input);

  if (!tokenKey) {
    return false;
  }

  try {
    await pool.query(
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
    console.log(`[DB] Failed to save token cache for ${input}: ${error.message}`);
    return false;
  }
}

export async function getAnalysisFromDb(input, {
  pool = dbPool,
  ready = dbReady,
} = {}) {
  if (!pool || !ready || !input) {
    return null;
  }

  const tokenKey = getCacheKey(input);

  if (!tokenKey) {
    return null;
  }

  try {
    const result = await pool.query(
      `
      SELECT payload, analyzed_at, updated_at
      FROM token_analysis_cache
      WHERE token_key = $1
      LIMIT 1
      `,
      [tokenKey]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const row = result.rows[0];
    const payload = row.payload || null;

    if (!payload) {
      return null;
    }

    const updatedAtMs = new Date(row.updated_at || row.analyzed_at || Date.now()).getTime();
    const ageMs = Math.max(0, Date.now() - updatedAtMs);

    setCachedAnalysis(input, payload);

    if (payload.tokenAddress) {
      setCachedAnalysis(payload.tokenAddress, payload);
    }

    if (payload.tokenSymbol) {
      setCachedAnalysis(payload.tokenSymbol, payload);
    }

    return {
      data: payload,
      ageMs,
      analyzedAt: row.analyzed_at,
      updatedAt: row.updated_at
    };
  } catch (error) {
    console.log(`[DB] Failed to read token cache for ${input}: ${error.message}`);
    return null;
  }
}

export async function saveAnalysisEverywhere(input, data, options = {}) {
  setCachedAnalysis(input, data);
  await saveAnalysisToDb(input, data, options);

  if (data?.tokenAddress && data.tokenAddress !== input) {
    setCachedAnalysis(data.tokenAddress, data);
    await saveAnalysisToDb(data.tokenAddress, data, options);
  }

  if (data?.tokenSymbol && data.tokenSymbol !== input) {
    setCachedAnalysis(data.tokenSymbol, data);
    await saveAnalysisToDb(data.tokenSymbol, data, options);
  }
}
