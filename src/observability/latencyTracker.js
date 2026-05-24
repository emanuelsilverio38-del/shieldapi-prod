export function startLatencyTimer() {
  return process.hrtime.bigint();
}

export function latencyMs(startedAt) {
  const start = typeof startedAt === 'bigint'
    ? startedAt
    : BigInt(startedAt || process.hrtime.bigint());

  const diffNs = process.hrtime.bigint() - start;
  return Number((Number(diffNs) / 1_000_000).toFixed(2));
}

export async function measureAsync(operation, fn) {
  const startedAt = startLatencyTimer();

  try {
    const result = await fn();
    return {
      ok: true,
      operation,
      result,
      latencyMs: latencyMs(startedAt),
    };
  } catch (error) {
    error.latencyMs = latencyMs(startedAt);
    error.operation = operation;
    throw error;
  }
}
