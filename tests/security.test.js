import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeLiquidity } from '../src/security/liquidityRisk.js';
import { analyzeAuthorities } from '../src/security/solanaAuthorities.js';
import { checkRugcheck } from '../src/security/rugcheckClient.js';

test('liquidity risk blocks very low liquidity', () => {
  const result = analyzeLiquidity({ liquidityUsd: 1000, volume24h: 10_000 });

  assert.equal(result.risk, 'HIGH');
  assert.ok(result.blockingReasons.includes('Liquidity too low'));
});

test('authority risk blocks active freeze authority', () => {
  const result = analyzeAuthorities({
    checked: true,
    freezeAuthority: true,
  });

  assert.equal(result.risk, 'HIGH');
  assert.ok(result.blockingReasons.includes('Freeze authority active'));
});

test('rugcheck is disabled safely without credentials', async () => {
  const result = await checkRugcheck('TOKEN', { enabled: false });

  assert.equal(result.checked, false);
  assert.equal(result.status, 'DISABLED');
});
