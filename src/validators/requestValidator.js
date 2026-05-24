export function validationOk(value = {}) {
  return {
    ok: true,
    ...value,
  };
}

export function validationError(error, message, extra = {}) {
  return {
    ok: false,
    error,
    message,
    ...extra,
  };
}

export function validateHttpMethod(req, expectedMethod) {
  const actual = String(req?.method || '').toUpperCase();
  const expected = String(expectedMethod || '').toUpperCase();

  if (!expected) {
    return validationError(
      'MISSING_EXPECTED_METHOD',
      'Expected HTTP method is required.'
    );
  }

  if (actual !== expected) {
    return validationError(
      'METHOD_NOT_ALLOWED',
      `Expected ${expected} request.`,
      {
        expected,
        actual,
      }
    );
  }

  return validationOk({
    method: actual,
  });
}

export function getUrl(req) {
  return new URL(req?.url || '/', 'http://localhost');
}

export function getQueryParam(req, name, fallback = null) {
  const url = getUrl(req);
  const value = url.searchParams.get(name);

  if (value === null || value === undefined || value === '') {
    return fallback;
  }

  return value;
}

export function validateRequiredFields(source = {}, fields = []) {
  const missing = fields.filter((field) => {
    const value = source?.[field];
    return value === undefined || value === null || value === '';
  });

  if (missing.length > 0) {
    return validationError(
      'MISSING_REQUIRED_FIELDS',
      `Missing required fields: ${missing.join(', ')}.`,
      {
        missing,
      }
    );
  }

  return validationOk();
}

export function validateJsonContentType(req, {
  required = false,
} = {}) {
  const contentType = String(req?.headers?.['content-type'] || '').toLowerCase();

  if (!contentType) {
    return required
      ? validationError(
          'MISSING_CONTENT_TYPE',
          'Content-Type header is required.'
        )
      : validationOk({
          contentType: '',
        });
  }

  if (!contentType.includes('application/json')) {
    return validationError(
      'UNSUPPORTED_CONTENT_TYPE',
      'Content-Type must be application/json.',
      {
        contentType,
      }
    );
  }

  return validationOk({
    contentType,
  });
}

export function validateBodySize(length, {
  maxBytes = 1_000_000,
} = {}) {
  const size = Number(length || 0);

  if (!Number.isFinite(size) || size < 0) {
    return validationError(
      'INVALID_BODY_SIZE',
      'Request body size is invalid.'
    );
  }

  if (size > maxBytes) {
    return validationError(
      'REQUEST_BODY_TOO_LARGE',
      `Request body must be ${maxBytes} bytes or smaller.`,
      {
        size,
        maxBytes,
      }
    );
  }

  return validationOk({
    size,
    maxBytes,
  });
}
