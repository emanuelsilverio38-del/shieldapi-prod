function getTokenKey(input, analysis = {}) {
  const value =
    analysis.tokenAddress ||
    analysis.tokenSymbol ||
    input ||
    '';

  return String(value).trim().toLowerCase();
}

function numberOrNull(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function getAnalyzedAt(analysis = {}) {
  const parsed = Date.parse(analysis.analyzedAt || analysis.updatedAt || new Date().toISOString());
  return Number.isFinite(parsed) ? new Date(parsed) : new Date();
}

export async function saveTokenAnalysisHistory(pool, input, analysis = {}) {
  if (!pool || !input || !analysis) {
    return null;
  }

  const tokenKey = getTokenKey(input, analysis);

  if (!tokenKey) {
    return null;
  }

  const result = await pool.query(
    `
    INSERT INTO token_analysis_history (
      token_key,
      token_address,
      token_symbol,
      chain,
      status,
      risk_level,
      risk_score,
      security_score,
      opportunity_score,
      liquidity_usd,
      volume24h,
      holder_concentration,
      blocking_reasons,
      warnings,
      reasons,
      payload,
      analyzed_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
    RETURNING *
    `,
    [
      tokenKey,
      analysis.tokenAddress || null,
      analysis.tokenSymbol || null,
      analysis.chain || analysis.chainId || 'solana',
      analysis.status || null,
      analysis.riskLevel || null,
      numberOrNull(analysis.riskScore),
      numberOrNull(analysis.securityScore),
      numberOrNull(analysis.opportunityScore),
      numberOrNull(analysis.liquidity),
      numberOrNull(analysis.volume24h),
      numberOrNull(analysis.security?.holders?.top10Pct),
      JSON.stringify(analysis.blockingReasons || []),
      JSON.stringify(analysis.warnings || []),
      JSON.stringify(analysis.reasons || []),
      JSON.stringify(analysis),
      getAnalyzedAt(analysis),
    ]
  );

  return result.rows[0] || null;
}

export async function getLatestTokenHistory(pool, input, {
  limit = 20,
} = {}) {
  if (!pool || !input) {
    return [];
  }

  const tokenKey = String(input).trim().toLowerCase();

  const result = await pool.query(
    `
    SELECT *
    FROM token_analysis_history
    WHERE token_key = $1
    ORDER BY created_at DESC
    LIMIT $2
    `,
    [tokenKey, Number(limit)]
  );

  return result.rows;
}
