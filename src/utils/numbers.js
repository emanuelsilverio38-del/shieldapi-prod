export function numberValue(value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return 0;
  }

  return parsed;
}

export function roundNumber(value, decimals = 2) {
  const parsed = numberValue(value);
  const factor = 10 ** decimals;

  return Math.round(parsed * factor) / factor;
}

export function percentageChange(current, previous) {
  const currentValue = numberValue(current);
  const previousValue = numberValue(previous);

  if (previousValue <= 0) {
    return 0;
  }

  return ((currentValue - previousValue) / previousValue) * 100;
}