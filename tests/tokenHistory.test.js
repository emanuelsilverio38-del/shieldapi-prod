import test from 'node:test';
import assert from 'node:assert/strict';

import {
  saveTokenAnalysisHistory,
} from '../src/db/tokenHistoryRepository.js';

test('saveTokenAnalysisHistory writes normalized analysis row', async () => {
  const calls = [];
  const pool = {
    async query(sql, values) {
      calls.push({ sql, values });
      return {
        rows: [{
          id: 1,
          token_key: values[0],
          status: values[4],
        }],
      };
    },
  };

  const row = await saveTokenAnalysisHistory(pool, 'BONK', {
    tokenSymbol: 'BONK',
    status: 'APPROVED',
    riskScore: 12,
    securityScore: 88,
    opportunityScore: 70,
    blockingReasons: [],
    warnings: [],
    reasons: ['Healthy liquidity'],
  });

  assert.equal(row.token_key, 'bonk');
  assert.equal(row.status, 'APPROVED');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].values[0], 'bonk');
});
