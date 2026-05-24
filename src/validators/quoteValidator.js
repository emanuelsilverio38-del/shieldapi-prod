import { validateSolanaAddress } from './solanaAddressValidator.js';
import { validationError, validationOk } from './requestValidator.js';

export function validatePositiveAmount(value, {
  field = 'amount',
} = {}) {
  const amount = Number(value);

  if (!Number.isFinite(amount) || amount <= 0) {
    return validationError(
      'INVALID_AMOUNT',
      `${field} must be a positive number.`,
      {
        field,
      }
    );
  }

  return validationOk({
    field,
    value: amount,
  });
}

export function validateSlippageBps(value, {
  min = 1,
  max = 2000,
} = {}) {
  const slippageBps = Number(value);

  if (!Number.isInteger(slippageBps) || slippageBps < min || slippageBps > max) {
    return validationError(
      'INVALID_SLIPPAGE_BPS',
      `slippageBps must be an integer between ${min} and ${max}.`,
      {
        min,
        max,
      }
    );
  }

  return validationOk({
    slippageBps,
  });
}

export function validateQuoteRequest(input = {}) {
  const inputMint = validateSolanaAddress(input.inputMint, {
    field: 'inputMint',
  });

  if (!inputMint.ok) return inputMint;

  const outputMint = validateSolanaAddress(input.outputMint, {
    field: 'outputMint',
  });

  if (!outputMint.ok) return outputMint;

  const amount = validatePositiveAmount(input.amount);
  if (!amount.ok) return amount;

  const slippage = validateSlippageBps(input.slippageBps ?? 100);
  if (!slippage.ok) return slippage;

  return validationOk({
    inputMint: inputMint.value,
    outputMint: outputMint.value,
    amount: amount.value,
    slippageBps: slippage.slippageBps,
  });
}

export function validatePrepareSwapRequest(input = {}) {
  const quote = validateQuoteRequest(input);

  if (!quote.ok) return quote;

  const userPublicKey = validateSolanaAddress(input.userPublicKey, {
    field: 'userPublicKey',
  });

  if (!userPublicKey.ok) return userPublicKey;

  return validationOk({
    ...quote,
    userPublicKey: userPublicKey.value,
  });
}
