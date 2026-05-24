import { isLikelySolanaAddress } from './solanaAddressValidator.js';
import { validationError, validationOk } from './requestValidator.js';

const SUPPORTED_CHAINS = new Set(['solana']);
const SUPPORTED_ANALYZE_MODES = new Set(['full', 'fast', 'submitted']);
const TOKEN_SYMBOL_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

export function normalizeAnalyzeInput(value) {
  return String(value || '').trim();
}

export function validateAnalyzeInput({
  address = null,
  token = null,
  mint = null,
  chain = 'solana',
  mode = 'full',
} = {}) {
  const normalizedChain = String(chain || 'solana').toLowerCase().trim();
  const normalizedMode = String(mode || 'full').toLowerCase().trim();
  const input = normalizeAnalyzeInput(address || mint || token);

  if (!SUPPORTED_CHAINS.has(normalizedChain)) {
    return validationError(
      'UNSUPPORTED_CHAIN',
      'Only solana is currently supported.',
      {
        chain: normalizedChain,
      }
    );
  }

  if (!SUPPORTED_ANALYZE_MODES.has(normalizedMode)) {
    return validationError(
      'INVALID_ANALYZE_MODE',
      'Analyze mode must be full, fast or submitted.',
      {
        mode: normalizedMode,
      }
    );
  }

  if (!input) {
    return validationError(
      'MISSING_TOKEN_INPUT',
      'Use address, mint or token.'
    );
  }

  if (address || mint) {
    if (!isLikelySolanaAddress(input)) {
      return validationError(
        'INVALID_TOKEN_ADDRESS',
        'Token address must be a valid Solana base58 address.',
        {
          value: input,
        }
      );
    }

    return validationOk({
      input,
      inputType: 'address',
      chain: normalizedChain,
      mode: normalizedMode,
    });
  }

  if (!TOKEN_SYMBOL_PATTERN.test(input)) {
    return validationError(
      'INVALID_TOKEN_SYMBOL',
      'Token symbol contains unsupported characters.',
      {
        value: input,
      }
    );
  }

  return validationOk({
    input,
    inputType: isLikelySolanaAddress(input) ? 'address' : 'symbol',
    chain: normalizedChain,
    mode: normalizedMode,
  });
}
