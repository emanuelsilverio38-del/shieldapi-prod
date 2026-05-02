import { analyzeWithDexscreener } from './dexscreenerClient.js';

export async function analyzeTokenSafety(input, options = {}) {
  const cleanInput = String(input || '').trim();

  if (!cleanInput) {
    return {
      httpStatus: 400,
      data: {
        status: 'ERROR',
        riskLevel: 'UNKNOWN',
        riskScore: null,
        opportunityScore: 0,
        reason: 'Token input is required.',
        reasons: ['Token input is required.'],
        security: {
          dex: null,
          rugcheck: null,
          authorities: null,
          holders: null,
          creator: null
        }
      }
    };
  }

  const dexResult = await analyzeWithDexscreener(cleanInput);

  const enrichedData = {
    ...dexResult.data,
    security: {
      dex: {
        checked: true,
        source: 'dexscreener',
        status: dexResult.data.status,
        riskLevel: dexResult.data.riskLevel,
        riskScore: dexResult.data.riskScore,
        reasons: dexResult.data.reasons || []
      },
      rugcheck: {
        checked: false,
        source: 'rugcheck',
        status: 'PENDING_IN_V4_8'
      },
      authorities: {
        checked: false,
        status: 'PENDING_IN_V4_8'
      },
      holders: {
        checked: false,
        status: 'PENDING_IN_V4_8'
      },
      creator: {
        checked: false,
        status: 'PENDING_IN_V4_8'
      }
    },
    securityVersion: options.securityVersion || '4.8-dev'
  };

  return {
    ...dexResult,
    data: enrichedData
  };
}