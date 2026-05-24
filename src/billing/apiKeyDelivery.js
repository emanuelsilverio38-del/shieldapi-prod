export async function storeApiKeyDelivery(pool, {
  sessionId,
  clientId,
  apiKey,
} = {}) {
  if (!pool || !sessionId || !clientId || !apiKey) {
    return null;
  }

  const result = await pool.query(
    `
    INSERT INTO api_key_delivery (session_id, client_id, api_key)
    VALUES ($1,$2,$3)
    ON CONFLICT (session_id) DO NOTHING
    RETURNING *
    `,
    [sessionId, clientId, apiKey]
  );

  return result.rows[0] || null;
}

export async function consumeApiKeyDelivery(pool, sessionId) {
  if (!pool || !sessionId) {
    return null;
  }

  const result = await pool.query(
    `
    UPDATE api_key_delivery
    SET consumed_at = NOW()
    WHERE session_id = $1
      AND consumed_at IS NULL
      AND expires_at > NOW()
    RETURNING *
    `,
    [sessionId]
  );

  return result.rows[0] || null;
}
