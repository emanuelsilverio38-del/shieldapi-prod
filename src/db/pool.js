import { Pool } from 'pg';

import { env } from '../config/env.js';

export let dbPool = null;
export let dbReady = false;
export let dbLastError = null;

export function createDbPool() {
  if (!env.DATABASE_ENABLED) {
    dbPool = null;
    dbReady = false;
    return null;
  }

  if (dbPool) {
    return dbPool;
  }

  dbPool = new Pool({
    connectionString: env.DATABASE_URL,
    max: env.DB_POOL_MAX,
    idleTimeoutMillis: env.DB_IDLE_TIMEOUT_MS,
    connectionTimeoutMillis: env.DB_CONNECTION_TIMEOUT_MS,
    ssl: env.DB_SSL
  });

  return dbPool;
}

export async function testDatabaseConnection() {
  if (!dbPool) {
    dbReady = false;
    return false;
  }

  try {
    await dbPool.query('SELECT 1');
    dbReady = true;
    dbLastError = null;
    return true;
  } catch (error) {
    dbReady = false;
    dbLastError = error.message;
    return false;
  }
}

export function getDatabaseStatus() {
  return {
    enabled: env.DATABASE_ENABLED,
    ready: dbReady,
    lastError: dbLastError
  };
}

export async function closeDatabasePool() {
  if (!dbPool) {
    return;
  }

  await dbPool.end();
  dbPool = null;
  dbReady = false;
}