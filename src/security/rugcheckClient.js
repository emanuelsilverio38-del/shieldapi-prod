export async function checkRugcheck(input, {
  enabled = false,
} = {}) {
  if (!enabled) {
    return {
      checked: false,
      source: 'rugcheck',
      status: 'DISABLED',
      flags: [],
    };
  }

  return {
    checked: false,
    source: 'rugcheck',
    status: 'PENDING_INTEGRATION',
    token: input,
    flags: [],
  };
}
