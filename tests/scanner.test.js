import test from 'node:test';
import assert from 'node:assert/strict';

import {
  filterNewDiscoveredTokens,
  rankScannerCandidates,
  resetScannerState,
  shouldAlertForAnalysis,
} from '../src/scanner/index.js';

test('scanner discovery filters repeated tokens', () => {
  resetScannerState();

  const first = filterNewDiscoveredTokens([
    { symbol: 'AAA', source: 'test' },
    { symbol: 'AAA', source: 'test' },
    { symbol: 'BBB', source: 'test' },
  ]);

  assert.equal(first.length, 2);

  const second = filterNewDiscoveredTokens([
    { symbol: 'AAA', source: 'test' },
  ]);

  assert.equal(second.length, 0);
});

test('scanner ranking prefers safer stronger candidates', () => {
  const ranked = rankScannerCandidates([
    { symbol: 'RISKY', riskScore: 90, securityScore: 10, opportunityScore: 99 },
    { symbol: 'SAFE', riskScore: 10, securityScore: 90, opportunityScore: 70 },
  ]);

  assert.equal(ranked[0].symbol, 'SAFE');
});

test('scanner alert triggers for blocked tokens', () => {
  assert.equal(shouldAlertForAnalysis({ status: 'BLOCKED' }), true);
});
