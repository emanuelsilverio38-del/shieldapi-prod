export async function recordUsageEvent(pool, {
  clientId = null,
  route = null,
  method = null,
  statusCode = null,
  responseTimeMs = null,
  tokenAddress = null,
  cacheHit = false,
  dbHit = false,
  ip = null,
  userAgent = null,
  metadata = {},
} = {}) {
  if (!pool) {
    return null;
  }

  const result = await pool.query(
    `
    INSERT INTO api_usage_events (
      client_id,
      route,
      method,
      status_code,
      response_time_ms,
      token_address,
      cache_hit,
      db_hit,
      ip,
      user_agent,
      metadata,
      created_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
    RETURNING *
    `,
    [
      clientId,
      route,
      method,
      statusCode,
      responseTimeMs,
      tokenAddress,
      cacheHit,
      dbHit,
      ip,
      userAgent,
      JSON.stringify(metadata || {}),
    ]
  );

  return result.rows[0];
}

export async function getClientUsageSummary(pool, clientId, {
  periodStart = null,
  periodEnd = null,
} = {}) {
  if (!pool || !clientId) {
    return {
      totalRequests: 0,
      cacheHits: 0,
      dbHits: 0,
      avgResponseTimeMs: null,
      byRoute: [],
    };
  }

  const values = [clientId];
  const filters = ['client_id = $1'];

  if (periodStart) {
    values.push(periodStart);
    filters.push(`created_at >= $${values.length}`);
  }

  if (periodEnd) {
    values.push(periodEnd);
    filters.push(`created_at < $${values.length}`);
  }

  const whereSql = `WHERE ${filters.join(' AND ')}`;

  const totalResult = await pool.query(
    `
    SELECT
      COUNT(*)::int AS total_requests,
      COALESCE(SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END), 0)::int AS cache_hits,
      COALESCE(SUM(CASE WHEN db_hit THEN 1 ELSE 0 END), 0)::int AS db_hits,
      ROUND(AVG(response_time_ms))::int AS avg_response_time_ms
    FROM api_usage_events
    ${whereSql}
    `,
    values
  );

  const routeResult = await pool.query(
    `
    SELECT
      route,
      COUNT(*)::int AS requests,
      COALESCE(SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END), 0)::int AS cache_hits,
      COALESCE(SUM(CASE WHEN db_hit THEN 1 ELSE 0 END), 0)::int AS db_hits,
      ROUND(AVG(response_time_ms))::int AS avg_response_time_ms
    FROM api_usage_events
    ${whereSql}
    GROUP BY route
    ORDER BY requests DESC
    `,
    values
  );

  const total = totalResult.rows[0] || {};

  return {
    totalRequests: Number(total.total_requests || 0),
    cacheHits: Number(total.cache_hits || 0),
    dbHits: Number(total.db_hits || 0),
    avgResponseTimeMs: total.avg_response_time_ms,
    byRoute: routeResult.rows,
  };
}

export async function getGlobalUsageSummary(pool, {
  periodStart = null,
  periodEnd = null,
  limit = 20,
} = {}) {
  if (!pool) {
    return {
      totalRequests: 0,
      byRoute: [],
      topClients: [],
    };
  }

  const values = [];
  const filters = [];

  if (periodStart) {
    values.push(periodStart);
    filters.push(`e.created_at >= $${values.length}`);
  }

  if (periodEnd) {
    values.push(periodEnd);
    filters.push(`e.created_at < $${values.length}`);
  }

  const whereSql = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

  const totalResult = await pool.query(
    `
    SELECT COUNT(*)::int AS total_requests
    FROM api_usage_events e
    ${whereSql}
    `,
    values
  );

  const routeResult = await pool.query(
    `
    SELECT
      e.route,
      COUNT(*)::int AS requests
    FROM api_usage_events e
    ${whereSql}
    GROUP BY e.route
    ORDER BY requests DESC
    LIMIT $${values.length + 1}
    `,
    [...values, Number(limit)]
  );

  const clientResult = await pool.query(
    `
    SELECT
      c.id,
      c.name,
      c.email,
      c.plan,
      COUNT(e.*)::int AS requests
    FROM api_usage_events e
    LEFT JOIN api_clients c ON c.id = e.client_id
    ${whereSql}
    GROUP BY c.id, c.name, c.email, c.plan
    ORDER BY requests DESC
    LIMIT $${values.length + 1}
    `,
    [...values, Number(limit)]
  );

  return {
    totalRequests: Number(totalResult.rows?.[0]?.total_requests || 0),
    byRoute: routeResult.rows,
    topClients: clientResult.rows,
  };
}

export async function getRecentUsageEvents(pool, {
  clientId = null,
  limit = 50,
} = {}) {
  if (!pool) {
    return [];
  }

  const values = [];
  const filters = [];

  if (clientId) {
    values.push(clientId);
    filters.push(`client_id = $${values.length}`);
  }

  values.push(Number(limit));
  const limitParam = `$${values.length}`;

  const whereSql = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

  const result = await pool.query(
    `
    SELECT
      e.*,
      c.name AS client_name,
      c.email AS client_email,
      c.plan AS client_plan
    FROM api_usage_events e
    LEFT JOIN api_clients c ON c.id = e.client_id
    ${whereSql}
    ORDER BY e.created_at DESC
    LIMIT ${limitParam}
    `,
    values
  );

  return result.rows;
}