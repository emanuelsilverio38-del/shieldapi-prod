import https from 'https';

import { env } from '../config/env.js';

export function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-api-key, authorization, stripe-signature',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });

  res.end(JSON.stringify(payload, null, 2));
}

export function sendHtml(res, statusCode, html) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });

  res.end(html);
}

export function getJson(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { timeout: env.EXTERNAL_TIMEOUT_MS }, (apiRes) => {
      let data = '';

      apiRes.on('data', (chunk) => {
        data += chunk;
      });

      apiRes.on('end', () => {
        try {
          const parsed = JSON.parse(data);

          if (apiRes.statusCode < 200 || apiRes.statusCode >= 300) {
            const error = new Error(`External API HTTP ${apiRes.statusCode}`);
            error.statusCode = apiRes.statusCode;
            error.payload = parsed;
            reject(error);
            return;
          }

          resolve(parsed);
        } catch {
          reject(new Error('Invalid response from external API'));
        }
      });
    });

    request.on('timeout', () => {
      request.destroy(new Error(`External API timeout after ${env.EXTERNAL_TIMEOUT_MS}ms`));
    });

    request.on('error', reject);
  });
}

export function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;

      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error('Request body too large'));
      }
    });

    req.on('end', () => {
      if (!body.trim()) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });

    req.on('error', reject);
  });
}

export function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalLength = 0;

    req.on('data', (chunk) => {
      chunks.push(chunk);
      totalLength += chunk.length;

      if (totalLength > 2_000_000) {
        req.destroy();
        reject(new Error('Webhook body too large'));
      }
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks));
    });

    req.on('error', reject);
  });
}