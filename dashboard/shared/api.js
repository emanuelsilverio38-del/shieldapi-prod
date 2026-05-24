export const DEFAULT_API_BASE = 'https://zucchini-caring-production.up.railway.app';

export function getApiBase() {
  return localStorage.getItem('shieldapi_base_url') || DEFAULT_API_BASE;
}

export function setApiBase(value) {
  localStorage.setItem('shieldapi_base_url', String(value || DEFAULT_API_BASE).trim());
}

export function getApiKey(storageKey = 'shieldapi_api_key') {
  return localStorage.getItem(storageKey) || '';
}

export function setApiKey(value, storageKey = 'shieldapi_api_key') {
  localStorage.setItem(storageKey, String(value || '').trim());
}

export async function shieldFetch(path, {
  method = 'GET',
  apiKey = getApiKey(),
  body = null,
} = {}) {
  const headers = {};

  if (apiKey) headers['x-api-key'] = apiKey;
  if (body !== null) headers['Content-Type'] = 'application/json';

  const response = await fetch(`${getApiBase()}${path}`, {
    method,
    headers,
    body: body === null ? undefined : JSON.stringify(body),
  });

  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json')
    ? await response.json()
    : await response.text();

  return {
    ok: response.ok,
    status: response.status,
    data,
  };
}
