import test from 'node:test';
import assert from 'node:assert/strict';

import { buildHealthResponse } from '../src/routes/health.js';

test('health response uses context version and db readiness', async () => {
  const result = await buildHealthResponse({
    version: '4.7',
    databaseEnabled: true,
    dbReady: true,
    modularRoutesReady: 17,
  });

  assert.equal(result.version, '4.7');
  assert.equal(result.database.configured, true);
  assert.equal(result.database.ready, true);
  assert.equal(result.routes.modularRoutesReady, 17);
});
