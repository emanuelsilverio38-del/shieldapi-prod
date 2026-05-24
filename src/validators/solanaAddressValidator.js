const BASE58_PATTERN = /^[1-9A-HJ-NP-Za-km-z]+$/;
const MIN_SOLANA_ADDRESS_LENGTH = 32;
const MAX_SOLANA_ADDRESS_LENGTH = 44;

export function normalizeSolanaAddress(value) {
  return String(value || '').trim();
}

export function isLikelySolanaAddress(value) {
  const address = normalizeSolanaAddress(value);

  return (
    address.length >= MIN_SOLANA_ADDRESS_LENGTH &&
    address.length <= MAX_SOLANA_ADDRESS_LENGTH &&
    BASE58_PATTERN.test(address)
  );
}

export function validateSolanaAddress(value, {
  field = 'address',
  required = true,
} = {}) {
  const address = normalizeSolanaAddress(value);

  if (!address) {
    return required
      ? {
          ok: false,
          field,
          error: 'MISSING_SOLANA_ADDRESS',
          message: `${field} is required.`,
        }
      : {
          ok: true,
          field,
          value: '',
        };
  }

  if (!isLikelySolanaAddress(address)) {
    return {
      ok: false,
      field,
      error: 'INVALID_SOLANA_ADDRESS',
      message: `${field} must be a valid Solana base58 address.`,
    };
  }

  return {
    ok: true,
    field,
    value: address,
  };
}

export function validateTokenMint(value, options = {}) {
  return validateSolanaAddress(value, {
    field: 'tokenMint',
    ...options,
  });
}

export function validateUserPublicKey(value, options = {}) {
  return validateSolanaAddress(value, {
    field: 'userPublicKey',
    ...options,
  });
}
