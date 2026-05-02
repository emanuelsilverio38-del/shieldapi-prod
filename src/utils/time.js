export function nowIso() {
  return new Date().toISOString();
}

export function startTimer() {
  return process.hrtime.bigint();
}

export function responseTimeMs(startedAt) {
  const diffNs = process.hrtime.bigint() - startedAt;
  return Number((Number(diffNs) / 1_000_000).toFixed(2));
}

export function unixSecondsToDate(value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    return null;
  }

  return new Date(parsed * 1000);
}