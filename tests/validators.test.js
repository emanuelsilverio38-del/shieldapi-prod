import test from 'node:test';
import assert from 'node:assert/strict';

import {
  validateAnalyzeInput,
  validateSolanaAddress,
} from '../src/validators/index.js';

test('validateAnalyzeInput accepts token symbols', () => {
  const result = validateAnalyzeInput({ token: 'BONK' });
  assert.equal(result.ok, true);
  assert.equal(result.inputType, 'symbol');
});

test('validateSolanaAddress rejects malformed addresses', () => {
  const result = validateSolanaAddress('not a solana address');
  assert.equal(result.ok, false);
  assert.equal(result.error, 'INVALID_SOLANA_ADDRESS');
});
