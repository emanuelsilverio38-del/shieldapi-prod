import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildDecision,
} from '../src/security/riskScoring.js';

test('risk scoring blocks when blocking reasons exist', () => {
  const result = buildDecision({
    riskScore: 20,
    blockingReasons: ['Freeze authority active'],
  });

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.securityScore, 80);
});

test('risk scoring approves low risk without blockers', () => {
  const result = buildDecision({ riskScore: 12 });
  assert.equal(result.status, 'APPROVED');
});
