function cleanEnvValue(value) {
  return String(value || '')
    .trim()
    .replace(/^['"]+|['"]+$/g, '')
    .replace(/\\n/g, '')
    .replace(/\r?\n/g, '')
    .trim();
}

function numberEnv(name, fallback) {
  const value = Number(process.env[name]);

  if (!Number.isFinite(value)) {
    return fallback;
  }

  return value;
}

function booleanEnv(name, fallback = false) {
  const value = process.env[name];

  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  return String(value).toLowerCase() === 'true';
}

export const env = {
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  API_KEY: cleanEnvValue(process.env.API_KEY),

  VERSION: process.env.SHIELD_API_VERSION || '4.7',
  SERVICE_NAME: 'ShieldAPI',

  CACHE_TTL_MS: numberEnv('CACHE_TTL_MS', 60_000),
  CACHE_MAX_ITEMS: numberEnv('CACHE_MAX_ITEMS', 50_000),
  EXTERNAL_TIMEOUT_MS: numberEnv('EXTERNAL_TIMEOUT_MS', 3000),
  RUGCHECK_ENABLED: booleanEnv('RUGCHECK_ENABLED', false),
  ONCHAIN_SECURITY_ENABLED: booleanEnv('ONCHAIN_SECURITY_ENABLED', false),
  HELIUS_API_KEY: cleanEnvValue(process.env.HELIUS_API_KEY),
  SOLANA_RPC_URL: cleanEnvValue(process.env.SOLANA_RPC_URL),

  RATE_LIMIT_WINDOW_MS: numberEnv('RATE_LIMIT_WINDOW_MS', 60_000),
  RATE_LIMIT_ENABLED: String(process.env.RATE_LIMIT_ENABLED || 'true').toLowerCase() !== 'false',

  DATABASE_URL: cleanEnvValue(process.env.DATABASE_URL),
  DATABASE_ENABLED: Boolean(cleanEnvValue(process.env.DATABASE_URL)),

  STRIPE_SECRET_KEY: cleanEnvValue(process.env.STRIPE_SECRET_KEY),
  STRIPE_WEBHOOK_SECRET: cleanEnvValue(process.env.STRIPE_WEBHOOK_SECRET),
  STRIPE_PRICE_STARTER: cleanEnvValue(process.env.STRIPE_PRICE_STARTER),
  STRIPE_PRICE_PRO: cleanEnvValue(process.env.STRIPE_PRICE_PRO),
  STRIPE_PRICE_ADVANCED: cleanEnvValue(process.env.STRIPE_PRICE_ADVANCED),

  APP_URL: cleanEnvValue(process.env.APP_URL) || 'https://zucchini-caring-production.up.railway.app',
  DASHBOARD_SUCCESS_URL:
    cleanEnvValue(process.env.DASHBOARD_SUCCESS_URL) ||
    'https://zucchini-caring-production.up.railway.app/billing/success',
  DASHBOARD_CANCEL_URL:
    cleanEnvValue(process.env.DASHBOARD_CANCEL_URL) ||
    'https://zucchini-caring-production.up.railway.app/billing/cancel',

  DB_POOL_MAX: numberEnv('DB_POOL_MAX', 5),
  DB_IDLE_TIMEOUT_MS: numberEnv('DB_IDLE_TIMEOUT_MS', 30_000),
  DB_CONNECTION_TIMEOUT_MS: numberEnv('DB_CONNECTION_TIMEOUT_MS', 5000),
  DB_SSL: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false },

  ENTERPRISE_RATE_LIMIT_PER_MINUTE: numberEnv('ENTERPRISE_RATE_LIMIT_PER_MINUTE', 5000),
  MASTER_RATE_LIMIT_PER_MINUTE: numberEnv('MASTER_RATE_LIMIT_PER_MINUTE', 5000)
};

export function getStripeEnabled() {
  return Boolean(env.STRIPE_SECRET_KEY);
}

export function getDatabaseEnabled() {
  return Boolean(env.DATABASE_URL);
}
