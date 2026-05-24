import { dbPool, getDatabaseStatus, testDatabaseConnection } from './pool.js';

export async function initDatabase() {
  if (!dbPool) {
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
        email TEXT,
        plan TEXT NOT NULL DEFAULT 'free',
        api_key_hash TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        billing_status TEXT,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        stripe_price_id TEXT,
        current_period_start TIMESTAMPTZ,
        current_period_end TIMESTAMPTZ,
        metadata JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        last_used_at TIMESTAMPTZ,
        disabled_at TIMESTAMPTZ
      )
    `);

    await dbPool.query(`ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS email TEXT`);
    await dbPool.query(`ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS billing_status TEXT`);
    await dbPool.query(`ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT`);
    await dbPool.query(`ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT`);
    await dbPool.query(`ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS stripe_price_id TEXT`);
    await dbPool.query(`ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS current_period_start TIMESTAMPTZ`);
    await dbPool.query(`ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS current_period_end TIMESTAMPTZ`);
    await dbPool.query(`ALTER TABLE api_clients ADD COLUMN IF NOT EXISTS metadata JSONB`);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_clients_status
      ON api_clients(status)
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_clients_plan
      ON api_clients(plan)
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_clients_stripe_customer
      ON api_clients(stripe_customer_id)
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_clients_stripe_subscription
      ON api_clients(stripe_subscription_id)
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS api_key_delivery (
        id BIGSERIAL PRIMARY KEY,
        session_id TEXT UNIQUE,
        client_id UUID,
        api_key TEXT NOT NULL,
        consumed_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '24 hours',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_key_delivery_session
      ON api_key_delivery(session_id)
    `);

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS api_usage_events (
        id BIGSERIAL PRIMARY KEY,
        client_id UUID,
        client_name TEXT,
        plan TEXT,
        route TEXT NOT NULL,
        method TEXT,
        status_code INTEGER,
        response_time_ms NUMERIC,
        token_address TEXT,
        cache_hit BOOLEAN DEFAULT false,
        db_hit BOOLEAN DEFAULT false,
        ip TEXT,
        user_agent TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        metadata JSONB
      )
    `);

    await dbPool.query(`ALTER TABLE api_usage_events ADD COLUMN IF NOT EXISTS client_name TEXT`);
    await dbPool.query(`ALTER TABLE api_usage_events ADD COLUMN IF NOT EXISTS plan TEXT`);
    await dbPool.query(`ALTER TABLE api_usage_events ADD COLUMN IF NOT EXISTS method TEXT`);
    await dbPool.query(`ALTER TABLE api_usage_events ADD COLUMN IF NOT EXISTS token_address TEXT`);
    await dbPool.query(`ALTER TABLE api_usage_events ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN DEFAULT false`);
    await dbPool.query(`ALTER TABLE api_usage_events ADD COLUMN IF NOT EXISTS db_hit BOOLEAN DEFAULT false`);
    await dbPool.query(`ALTER TABLE api_usage_events ADD COLUMN IF NOT EXISTS ip TEXT`);
    await dbPool.query(`ALTER TABLE api_usage_events ADD COLUMN IF NOT EXISTS user_agent TEXT`);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_usage_client_created
      ON api_usage_events(client_id, created_at DESC)
    `);

    await dbPool.query(`
      CREATE INDEX IF NOT EXISTS idx_api_usage_route_created
      ON api_usage_events(route, created_at DESC)
    `);

    await testDatabaseConnection();

    console.log('[DB] PostgreSQL migrations ready.');
    return true;
  } catch (error) {
    console.log('[DB] PostgreSQL migrations failed:', error.message);
    return false;
  }
}

export function getMigrationDatabaseStatus() {
  return getDatabaseStatus();
}
