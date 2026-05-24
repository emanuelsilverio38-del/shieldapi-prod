import { normalizePlan } from '../auth/plans.js';
import { validationError, validationOk } from './requestValidator.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_CLIENT_STATUSES = new Set(['active', 'disabled']);

export function validateClientId(clientId) {
  const value = String(clientId || '').trim();

  if (!value) {
    return validationError(
      'MISSING_CLIENT_ID',
      'clientId is required.'
    );
  }

  if (!UUID_PATTERN.test(value)) {
    return validationError(
      'INVALID_CLIENT_ID',
      'clientId must be a UUID.'
    );
  }

  return validationOk({
    clientId: value,
  });
}

export function validateEmail(email, {
  required = false,
} = {}) {
  const value = String(email || '').trim();

  if (!value) {
    return required
      ? validationError('MISSING_EMAIL', 'email is required.')
      : validationOk({ email: null });
  }

  if (!EMAIL_PATTERN.test(value)) {
    return validationError(
      'INVALID_EMAIL',
      'email must be a valid email address.'
    );
  }

  return validationOk({
    email: value,
  });
}

export function validateCreateClientRequest(body = {}) {
  const name = String(body.name || '').trim();

  if (!name) {
    return validationError(
      'MISSING_CLIENT_NAME',
      'Client name is required.'
    );
  }

  const email = validateEmail(body.email);
  if (!email.ok) return email;

  const plan = normalizePlan(body.plan || 'free');
  const status = String(body.status || 'active').toLowerCase().trim();

  if (!ALLOWED_CLIENT_STATUSES.has(status)) {
    return validationError(
      'INVALID_CLIENT_STATUS',
      'Client status must be active or disabled.',
      {
        status,
      }
    );
  }

  return validationOk({
    name,
    email: email.email,
    plan,
    status,
  });
}

export function validateDisableClientRequest(body = {}, query = {}) {
  return validateClientId(body.clientId || body.id || query.clientId || query.id);
}
