import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SHIELD_API_URL =
  process.env.SHIELD_API_URL || 'https://zucchini-caring-production.up.railway.app';

const SHIELD_API_KEY = process.env.SHIELD_API_KEY;

if (!SHIELD_API_KEY) {
  console.error('[CONFIG] Missing SHIELD_API_KEY environment variable.');
  console.error('[CONFIG] Run this first in PowerShell:');
  console.error('$env:SHIELD_API_KEY="YOUR_NEW_API_KEY"');
  process.exit(1);
}

const SCAN_INTERVAL_MS = 60_000;
const DISCOVERY_SCAN_DELAY_MS = 1200;

const DISCOVERY_PREFILTER = {
  minLiquidityUsd: 20000,
  minVolume24hUsd: 50000,
  minTxns24h: 300,
  minBuySellRatio: 0.9,
  maxDiscoveryPerLoop: 12
};

const DATA_DIR = path.join(__dirname, 'data');

const VAULT_FILES = {
  discoveryCandidates: path.join(DATA_DIR, 'discovery_candidates.json'),
  approvedCandidates: path.join(DATA_DIR, 'approved_candidates.json'),
  blockedTokens: path.join(DATA_DIR, 'blocked_tokens.json'),
  skippedTokens: path.join(DATA_DIR, 'skipped_tokens.json'),
  prefilterRejected: path.join(DATA_DIR, 'prefilter_rejected_tokens.json'),
  errors: path.join(DATA_DIR, 'scanner_errors.json'),
  scannerSummary: path.join(DATA_DIR, 'scanner_summary.json')
};

const OFFICIAL_WATCHLIST = [
  {
    label: 'BONK',
    address: 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263',
    source: 'OFFICIAL'
  },
  {
    label: 'WIF',
    address: 'EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm',
    source: 'OFFICIAL'
  },
  {
    label: 'POPCAT',
    address: '7GCihgDB8fe6KNjn2MYtkzZcRjQy3t9GHdC8uHYmW2hr',
    source: 'OFFICIAL'
  },
  {
    label: 'MEW',
    address: 'MEW1gQWJ3nEXg2qgERiKu7FAFj79PHvQVREQUzScPP5',
    source: 'OFFICIAL'
  },
  {
    label: 'MYRO',
    address: 'HhJpBhRRn4g56VsyLuT8DL5Bv31HkXqsrahTTUCZeZg4',
    source: 'OFFICIAL'
  },
  {
    label: 'BOME',
    address: 'ukHH6c7mMyiWCf1b9pnWe25TSpkDDt3H5pQZgZ74J82',
    source: 'OFFICIAL'
  },
  {
    label: 'SLERF',
    address: '9999FVbjHioTcoJpoBiSjpxHW6xEn3witVuXKqBh2RFQ',
    source: 'OFFICIAL'
  },
  {
    label: 'WATERCOIN_TEST',
    address: '9RFDHRx92t1SNM5Cd7kz3oQK1EmxdvEb3ZtRheFWpump',
    source: 'TEST_BLOCKED'
  }
];

const history = new Map();
const discoveredTokens = new Map();
const blockedMemory = new Set();
const skippedMemory = new Set();
const prefilterRejectedMemory = new Set();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function shortAddress(address) {
  if (!address || typeof address !== 'string') {
    return 'UNKNOWN';
  }

  if (address.length <= 12) {
    return address;
  }

  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function ensureVaultFiles() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const arrayFiles = [
    VAULT_FILES.discoveryCandidates,
    VAULT_FILES.approvedCandidates,
    VAULT_FILES.blockedTokens,
    VAULT_FILES.skippedTokens,
    VAULT_FILES.prefilterRejected,
    VAULT_FILES.errors
  ];

  for (const file of arrayFiles) {
    if (!fs.existsSync(file)) {
      writeJsonFile(file, []);
    }
  }

  if (!fs.existsSync(VAULT_FILES.scannerSummary)) {
    writeJsonFile(VAULT_FILES.scannerSummary, {
      version: '3.3.2',
      name: 'ScannerAgent Candidate Vault',
      createdAt: new Date().toISOString(),
      lastLoopAt: null,
      loopCount: 0,
      totals: {}
    });
  }
}

function readJsonFile(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      return fallback;
    }

    const raw = fs.readFileSync(file, 'utf8');

    if (!raw.trim()) {
      return fallback;
    }

    return JSON.parse(raw);
  } catch (error) {
    console.log(`[VAULT] Failed to read ${path.basename(file)}: ${error.message}`);
    return fallback;
  }
}

function writeJsonFile(file, data) {
  const tmpFile = `${file}.tmp`;

  fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmpFile, file);
}

function getRecordKey(record) {
  return (
    record?.tokenAddress ||
    record?.address ||
    record?.pairAddress ||
    record?.dexUrl ||
    record?.label ||
    null
  );
}

function upsertVaultRecord(file, record, options = {}) {
  const { sortByOpportunity = false, maxRecords = 5000 } = options;

  const now = new Date().toISOString();
  const rows = readJsonFile(file, []);
  const key = getRecordKey(record);

  if (!key) {
    return;
  }

  const index = rows.findIndex((row) => getRecordKey(row) === key);

  if (index >= 0) {
    const previous = rows[index];

    rows[index] = {
      ...previous,
      ...record,
      firstSeenAt: previous.firstSeenAt || record.firstSeenAt || now,
      lastSeenAt: now,
      scanCount: Number(previous.scanCount || 0) + 1
    };
  } else {
    rows.push({
      ...record,
      firstSeenAt: record.firstSeenAt || now,
      lastSeenAt: now,
      scanCount: 1
    });
  }

  let finalRows = rows;

  if (sortByOpportunity) {
    finalRows = rows
      .slice()
      .sort((a, b) => Number(b.opportunityScore || 0) - Number(a.opportunityScore || 0));
  }

  if (finalRows.length > maxRecords) {
    finalRows = finalRows.slice(0, maxRecords);
  }

  writeJsonFile(file, finalRows);
}

function loadVaultMemories() {
  const blockedRows = readJsonFile(VAULT_FILES.blockedTokens, []);
  const skippedRows = readJsonFile(VAULT_FILES.skippedTokens, []);
  const rejectedRows = readJsonFile(VAULT_FILES.prefilterRejected, []);
  const discoveryRows = readJsonFile(VAULT_FILES.discoveryCandidates, []);

  for (const row of blockedRows) {
    const key = row.tokenAddress || row.address;
    if (key) blockedMemory.add(key);
  }

  for (const row of skippedRows) {
    const key = row.tokenAddress || row.address;
    if (key) skippedMemory.add(key);
  }

  for (const row of rejectedRows) {
    const key = row.tokenAddress || row.address;
    if (key) prefilterRejectedMemory.add(key);
  }

  for (const row of discoveryRows) {
    const key = row.tokenAddress || row.address;

    if (key) {
      discoveredTokens.set(key, {
        ...row,
        firstSeenAt: row.firstSeenAt || new Date().toISOString(),
        lastSeenAt: row.lastSeenAt || new Date().toISOString()
      });
    }
  }

  console.log(`[VAULT] Loaded blocked memory: ${blockedMemory.size}`);
  console.log(`[VAULT] Loaded skipped memory: ${skippedMemory.size}`);
  console.log(`[VAULT] Loaded prefilter memory: ${prefilterRejectedMemory.size}`);
  console.log(`[VAULT] Loaded discovery memory: ${discoveredTokens.size}`);
}

function buildVaultRecord(result) {
  const item = result.item;
  const data = result.data || {};
  const alerts = result.alerts || [];
  const txns24h = data.txns24h || {};

  return {
    label: item.label,
    source: item.source,
    status: result.statusType,
    riskLevel: data.riskLevel || 'UNKNOWN',
    riskScore: Number(data.riskScore || 0),
    opportunityScore: Number(result.opportunityScore || 0),

    address: item.address,
    tokenAddress: data.tokenAddress || item.address,
    pairAddress: data.pairAddress || item.pairAddress || null,

    tokenName: data.tokenName || null,
    tokenSymbol: data.tokenSymbol || item.label || null,

    price: Number(data.price || 0),
    liquidity: Number(data.liquidity || 0),
    volume24h: Number(data.volume24h || 0),

    txns24h: {
      buys: Number(txns24h.buys || 0),
      sells: Number(txns24h.sells || 0),
      total: Number(txns24h.total || 0)
    },

    priceChange: {
      m5: Number(data?.priceChange?.m5 || 0),
      h1: Number(data?.priceChange?.h1 || 0),
      h6: Number(data?.priceChange?.h6 || 0),
      h24: Number(data?.priceChange?.h24 || 0)
    },

    dex: data.dex || item.dex || null,
    dexUrl: data.dexUrl || item.dexUrl || null,

    prefilter: item.prefilter || null,

    alerts: alerts.map((alert) => ({
      level: alert.level,
      message: alert.message
    }))
  };
}

function saveScanResultToVault(result) {
  if (!result || !result.item) {
    return;
  }

  const record = buildVaultRecord(result);

  if (result.item.source === 'DISCOVERY') {
    upsertVaultRecord(VAULT_FILES.discoveryCandidates, record, {
      sortByOpportunity: true,
      maxRecords: 5000
    });
  }

  if (result.statusType === 'APPROVED') {
    upsertVaultRecord(VAULT_FILES.approvedCandidates, record, {
      sortByOpportunity: true,
      maxRecords: 3000
    });
  }

  if (result.statusType === 'BLOCKED') {
    upsertVaultRecord(VAULT_FILES.blockedTokens, record, {
      sortByOpportunity: false,
      maxRecords: 5000
    });
  }

  if (result.statusType === 'SKIPPED') {
    upsertVaultRecord(VAULT_FILES.skippedTokens, record, {
      sortByOpportunity: false,
      maxRecords: 5000
    });
  }

  if (result.statusType === 'ERROR') {
    upsertVaultRecord(VAULT_FILES.errors, record, {
      sortByOpportunity: false,
      maxRecords: 3000
    });
  }
}

function savePrefilterRejectedToVault(item) {
  const record = {
    label: item.label,
    source: item.source,
    status: 'PREFILTER_REJECTED',
    address: item.address,
    tokenAddress: item.address,
    pairAddress: item.pairAddress || null,
    dex: item.dex || null,
    dexUrl: item.dexUrl || null,
    prefilter: item.prefilter || null,
    rejectReason: item?.prefilter?.rejectReason || 'unknown'
  };

  upsertVaultRecord(VAULT_FILES.prefilterRejected, record, {
    sortByOpportunity: false,
    maxRecords: 5000
  });
}

function saveErrorToVault(item, error) {
  upsertVaultRecord(
    VAULT_FILES.errors,
    {
      label: item.label,
      source: item.source,
      status: 'ERROR',
      address: item.address,
      tokenAddress: item.address,
      pairAddress: item.pairAddress || null,
      dex: item.dex || null,
      dexUrl: item.dexUrl || null,
      errorMessage: error.message,
      httpStatus: error.httpStatus || null,
      payload: error.payload || null
    },
    {
      sortByOpportunity: false,
      maxRecords: 3000
    }
  );
}

function isImageUrl(value) {
  if (!value || typeof value !== 'string') {
    return false;
  }

  return (
    value.startsWith('http://') ||
    value.startsWith('https://') ||
    value.includes('cdn.dexscreener.com') ||
    value.includes('/images/') ||
    value.includes('format=auto')
  );
}

function cleanText(value) {
  if (!value || typeof value !== 'string') {
    return '';
  }

  const cleaned = value
    .replace(/\s+/g, ' ')
    .replace(/[^\x20-\x7E]/g, '')
    .trim();

  if (!cleaned || isImageUrl(cleaned)) {
    return '';
  }

  return cleaned;
}

function buildCleanDiscoveryLabel(profile, address) {
  const candidates = [
    profile?.tokenSymbol,
    profile?.symbol,
    profile?.baseToken?.symbol,
    profile?.tokenName,
    profile?.name,
    profile?.baseToken?.name,
    profile?.header,
    profile?.description
  ];

  for (const candidate of candidates) {
    const cleaned = cleanText(candidate);

    if (cleaned && cleaned.length <= 40) {
      return cleaned;
    }
  }

  return shortAddress(address);
}

function numberValue(value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return 0;
  }

  return parsed;
}

function extractLiquidityUsd(pair) {
  return numberValue(pair?.liquidity?.usd);
}

function extractVolume24hUsd(pair) {
  return numberValue(pair?.volume?.h24);
}

function extractTxns24h(pair) {
  const buys = numberValue(pair?.txns?.h24?.buys);
  const sells = numberValue(pair?.txns?.h24?.sells);

  return {
    buys,
    sells,
    total: buys + sells
  };
}

function extractPriceChange(pair) {
  return {
    m5: numberValue(pair?.priceChange?.m5),
    h1: numberValue(pair?.priceChange?.h1),
    h6: numberValue(pair?.priceChange?.h6),
    h24: numberValue(pair?.priceChange?.h24)
  };
}

async function getJson(url) {
  const response = await fetch(url, {
    headers: {
      accept: 'application/json'
    }
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP ${response.status}: ${text}`);
  }

  return response.json();
}

function buildAnalyzeUrl(item) {
  const base = `${SHIELD_API_URL}/analyze`;

  return `${base}?address=${encodeURIComponent(item.address)}&key=${encodeURIComponent(SHIELD_API_KEY)}`;
}

async function callShieldAPI(item) {
  const url = buildAnalyzeUrl(item);

  const response = await fetch(url, {
    headers: {
      accept: 'application/json'
    }
  });

  const text = await response.text();

  let parsed;

  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = {
      raw: text
    };
  }

  if (!response.ok) {
    const reason = parsed?.reason || parsed?.error || text || 'Unknown API error';

    const error = new Error(reason);
    error.httpStatus = response.status;
    error.payload = parsed;

    throw error;
  }

  return parsed;
}

function getPreviousSnapshot(label) {
  const snapshots = history.get(label) || [];

  if (snapshots.length === 0) {
    return null;
  }

  return snapshots[snapshots.length - 1];
}

function createSnapshotFromData(data) {
  return {
    status: data.status,
    riskScore: Number(data.riskScore || 0),
    riskLevel: data.riskLevel || 'UNKNOWN',
    price: Number(data.price || 0),
    liquidity: Number(data.liquidity || 0),
    volume24h: Number(data.volume24h || 0),
    txns24hTotal: Number(data?.txns24h?.total || 0),
    buys24h: Number(data?.txns24h?.buys || 0),
    sells24h: Number(data?.txns24h?.sells || 0),
    priceChange5m: Number(data?.priceChange?.m5 || 0),
    priceChange1h: Number(data?.priceChange?.h1 || 0),
    priceChange24h: Number(data?.priceChange?.h24 || 0),
    dex: data.dex,
    pairAddress: data.pairAddress,
    tokenAddress: data.tokenAddress,
    tokenName: data.tokenName,
    tokenSymbol: data.tokenSymbol,
    dexUrl: data.dexUrl
  };
}

function saveSnapshot(label, snapshot) {
  const snapshots = history.get(label) || [];

  snapshots.push({
    ...snapshot,
    timestamp: Date.now()
  });

  if (snapshots.length > 30) {
    snapshots.shift();
  }

  history.set(label, snapshots);
}

function calculateChange(current, previous, field) {
  const currentValue = Number(current[field] || 0);
  const previousValue = Number(previous[field] || 0);

  if (previousValue <= 0) {
    return 0;
  }

  return ((currentValue - previousValue) / previousValue) * 100;
}

function calculateOpportunityScore(current, previous) {
  let score = 0;

  const buys24h = Number(current.buys24h || 0);
  const sells24h = Number(current.sells24h || 0);
  const buySellRatio = sells24h > 0 ? buys24h / sells24h : buys24h > 0 ? 99 : 0;

  if (current.status === 'APPROVED') {
    score += 25;
  }

  if (current.riskLevel === 'LOW') {
    score += 20;
  }

  if (current.liquidity >= 50000) {
    score += 15;
  } else if (current.liquidity >= 30000) {
    score += 10;
  } else if (current.liquidity >= 20000) {
    score += 5;
  }

  if (current.volume24h >= 250000) {
    score += 15;
  } else if (current.volume24h >= 50000) {
    score += 10;
  }

  if (current.txns24hTotal >= 1000) {
    score += 10;
  } else if (current.txns24hTotal >= 300) {
    score += 5;
  }

  if (buySellRatio >= 1.25) {
    score += 12;
  } else if (buySellRatio >= 1.05) {
    score += 8;
  } else if (buySellRatio >= 0.9) {
    score += 3;
  }

  if (current.priceChange5m > 0) {
    score += 5;
  }

  if (current.priceChange1h > 0) {
    score += 5;
  }

  if (previous) {
    const volumeChangePct = calculateChange(current, previous, 'volume24h');
    const txnsChangePct = calculateChange(current, previous, 'txns24hTotal');

    if (volumeChangePct >= 15) {
      score += 10;
    }

    if (txnsChangePct >= 15) {
      score += 10;
    }
  }

  if (buySellRatio < 0.15) {
    score -= 60;
  } else if (buySellRatio < 0.25) {
    score -= 45;
  } else if (buySellRatio < 0.5) {
    score -= 30;
  } else if (buySellRatio < 0.75) {
    score -= 15;
  } else if (buySellRatio < 0.9) {
    score -= 8;
  }

  if (current.priceChange5m <= -10) {
    score -= 15;
  } else if (current.priceChange5m <= -5) {
    score -= 8;
  }

  if (current.priceChange1h <= -20) {
    score -= 15;
  } else if (current.priceChange1h <= -10) {
    score -= 8;
  }

  score = Math.max(0, Math.min(score, 100));

  if (buySellRatio < 0.15) {
    score = Math.min(score, 25);
  } else if (buySellRatio < 0.25) {
    score = Math.min(score, 35);
  } else if (buySellRatio < 0.5) {
    score = Math.min(score, 50);
  } else if (buySellRatio < 0.75) {
    score = Math.min(score, 65);
  }

  return score;
}

function calculatePrefilterScore(metrics) {
  let score = 0;

  if (metrics.liquidityUsd >= 50000) {
    score += 30;
  } else if (metrics.liquidityUsd >= 30000) {
    score += 20;
  } else if (metrics.liquidityUsd >= 20000) {
    score += 10;
  }

  if (metrics.volume24hUsd >= 250000) {
    score += 25;
  } else if (metrics.volume24hUsd >= 100000) {
    score += 20;
  } else if (metrics.volume24hUsd >= 50000) {
    score += 10;
  }

  if (metrics.txns24hTotal >= 5000) {
    score += 20;
  } else if (metrics.txns24hTotal >= 1000) {
    score += 15;
  } else if (metrics.txns24hTotal >= 300) {
    score += 10;
  }

  if (metrics.buySellRatio >= 1.2) {
    score += 15;
  } else if (metrics.buySellRatio >= 1.0) {
    score += 10;
  } else if (metrics.buySellRatio >= 0.9) {
    score += 5;
  }

  if (metrics.priceChange5m > 0) {
    score += 5;
  }

  if (metrics.priceChange1h > 0) {
    score += 5;
  }

  return Math.min(score, 100);
}

function analyzeFrequency(label, current, previous, source) {
  const alerts = [];
  const opportunityScore = calculateOpportunityScore(current, previous);

  if (current.status === 'BLOCKED') {
    alerts.push({
      level: 'BLOCKED',
      message: `${label} is blocked by ShieldAPI. Risk level: ${current.riskLevel}. Risk score: ${current.riskScore}.`
    });

    return { alerts, opportunityScore };
  }

  if (current.status === 'WARNING') {
    alerts.push({
      level: 'WARNING',
      message: `${label} has medium risk. Manual review recommended.`
    });
  }

  if (!previous) {
    if (current.status === 'APPROVED') {
      alerts.push({
        level: 'FIRST_SCAN',
        message: `${label} approved on first scan. Waiting for history to detect frequency changes.`
      });
    }

    if (source === 'DISCOVERY' && current.status === 'APPROVED') {
      alerts.push({
        level: 'NEW_DISCOVERY',
        message: `${label} discovered automatically and passed ShieldAPI. Opportunity score: ${opportunityScore}/100.`
      });
    }

    return { alerts, opportunityScore };
  }

  const volumeChangePct = calculateChange(current, previous, 'volume24h');
  const txnsChangePct = calculateChange(current, previous, 'txns24hTotal');
  const liquidityChangePct = calculateChange(current, previous, 'liquidity');

  if (volumeChangePct >= 25) {
    alerts.push({
      level: 'VOLUME_SPIKE',
      message: `${label} volume increased ${volumeChangePct.toFixed(2)}% since last scan.`
    });
  }

  if (txnsChangePct >= 25) {
    alerts.push({
      level: 'TXNS_SPIKE',
      message: `${label} transaction activity increased ${txnsChangePct.toFixed(2)}% since last scan.`
    });
  }

  if (liquidityChangePct <= -20) {
    alerts.push({
      level: 'LIQUIDITY_DROP',
      message: `${label} liquidity dropped ${Math.abs(liquidityChangePct).toFixed(2)}% since last scan.`
    });
  }

  const buys24h = Number(current.buys24h || 0);
  const sells24h = Number(current.sells24h || 0);
  const buySellRatio = sells24h > 0 ? buys24h / sells24h : buys24h > 0 ? 99 : 0;

  if (sells24h > 0 && buySellRatio < 0.5) {
    alerts.push({
      level: 'SELL_PRESSURE',
      message: `${label} has strong sell pressure: buys/sells ratio ${buySellRatio.toFixed(2)} (${buys24h}/${sells24h}). Opportunity score was penalized.`
    });
  }

  if (current.priceChange5m >= 5 && current.txns24hTotal > previous.txns24hTotal) {
    alerts.push({
      level: 'MOMENTUM',
      message: `${label} shows short-term momentum: 5m price change ${current.priceChange5m}%.`
    });
  }

  if (
    current.status === 'APPROVED' &&
    current.riskLevel === 'LOW' &&
    volumeChangePct >= 15 &&
    txnsChangePct >= 15
  ) {
    alerts.push({
      level: 'AI_AGENT_SIGNAL',
      message: `${label} is heating up with low risk, rising volume and rising transaction frequency. Opportunity score: ${opportunityScore}/100.`
    });
  }

  if (source === 'DISCOVERY' && current.status === 'APPROVED' && opportunityScore >= 70) {
    alerts.push({
      level: 'DISCOVERY_CANDIDATE',
      message: `${label} is a strong discovered candidate. Opportunity score: ${opportunityScore}/100.`
    });
  }

  if (alerts.length === 0) {
    alerts.push({
      level: 'NORMAL',
      message: `${label} has no abnormal frequency signal in this scan.`
    });
  }

  return { alerts, opportunityScore };
}

function printTokenResult(item, data, alerts, opportunityScore) {
  console.log('');
  console.log('==================================================');
  console.log(`[SCAN] ${item.label}`);
  console.log('--------------------------------------------------');
  console.log(`Source:       ${item.source}`);
  console.log(`Status:       ${data.status}`);
  console.log(`Risk Level:   ${data.riskLevel}`);
  console.log(`Risk Score:   ${data.riskScore}`);
  console.log(`Opp. Score:   ${opportunityScore}/100`);
  console.log(`Price:        $${data.price}`);
  console.log(`Liquidity:    $${Number(data.liquidity || 0).toLocaleString('en-US')}`);
  console.log(`Volume 24h:   $${Number(data.volume24h || 0).toLocaleString('en-US')}`);
  console.log(`Txns 24h:     ${data?.txns24h?.total || 0}`);
  console.log(`Buys/Sells:   ${data?.txns24h?.buys || 0}/${data?.txns24h?.sells || 0}`);
  console.log(`DEX:          ${data.dex}`);
  console.log(`Pair:         ${data.pairAddress}`);
  console.log(`Token:        ${data.tokenAddress}`);
  console.log(`Dex URL:      ${data.dexUrl}`);

  console.log('');
  console.log('ALERTS:');

  for (const alert of alerts) {
    console.log(`- [${alert.level}] ${alert.message}`);
  }

  console.log('==================================================');
}

function printSkipped(item, reason) {
  console.log('');
  console.log('==================================================');
  console.log(`[SKIPPED] ${item.label}`);
  console.log('--------------------------------------------------');
  console.log(`Source:       ${item.source}`);
  console.log(`Address:      ${item.address}`);
  console.log(`Reason:       ${reason}`);
  console.log('==================================================');
}

function printPrefilterRejected(item) {
  console.log('');
  console.log('==================================================');
  console.log(`[PREFILTER_REJECTED] ${item.label}`);
  console.log('--------------------------------------------------');
  console.log(`Source:       ${item.source}`);
  console.log(`Address:      ${item.address}`);
  console.log(`Liq:          $${item.prefilter.liquidityUsd.toLocaleString('en-US')}`);
  console.log(`Vol 24h:      $${item.prefilter.volume24hUsd.toLocaleString('en-US')}`);
  console.log(`Txns 24h:     ${item.prefilter.txns24hTotal}`);
  console.log(`Buys/Sells:   ${item.prefilter.buys24h}/${item.prefilter.sells24h}`);
  console.log(`Buy/Sell:     ${item.prefilter.buySellRatio.toFixed(2)}`);
  console.log(`Pre Score:    ${item.prefilter.prefilterScore}/100`);
  console.log(`Reason:       ${item.prefilter.rejectReason}`);
  console.log('==================================================');
}

async function scanToken(item) {
  try {
    const previous = getPreviousSnapshot(item.label);
    const data = await callShieldAPI(item);
    const currentSnapshot = createSnapshotFromData(data);
    const { alerts, opportunityScore } = analyzeFrequency(
      item.label,
      currentSnapshot,
      previous,
      item.source
    );

    if (data.status === 'BLOCKED') {
      blockedMemory.add(item.address);
    }

    saveSnapshot(item.label, currentSnapshot);
    printTokenResult(item, data, alerts, opportunityScore);

    const result = {
      item,
      data,
      statusType: data.status,
      opportunityScore,
      alerts
    };

    saveScanResultToVault(result);

    return result;
  } catch (error) {
    if (item.source === 'DISCOVERY' && (error.httpStatus === 403 || error.httpStatus === 404)) {
      skippedMemory.add(item.address);
      printSkipped(item, 'SKIPPED_NOT_TRADABLE_OR_NOT_INDEXED');

      const result = {
        item,
        data: null,
        statusType: 'SKIPPED',
        opportunityScore: 0,
        alerts: [
          {
            level: 'SKIPPED_NOT_TRADABLE',
            message: `${item.label} is not tradable/indexed by ShieldAPI yet.`
          }
        ]
      };

      saveScanResultToVault(result);

      return result;
    }

    console.log('');
    console.log('==================================================');
    console.log(`[ERROR] ${item.label}`);
    console.log(`Source: ${item.source}`);
    console.log(`Address: ${item.address}`);
    console.log(`Reason: ${error.message}`);
    console.log('==================================================');

    saveErrorToVault(item, error);

    return {
      item,
      data: null,
      statusType: 'ERROR',
      opportunityScore: 0,
      alerts: [
        {
          level: 'ERROR',
          message: error.message
        }
      ]
    };
  }
}

function normalizeDiscoveredPair(pair) {
  const chainId = pair?.chainId;
  const address = pair?.baseToken?.address;

  if (chainId !== 'solana') {
    return null;
  }

  if (!address) {
    return null;
  }

  const txns = extractTxns24h(pair);
  const priceChange = extractPriceChange(pair);
  const buys = txns.buys;
  const sells = txns.sells;
  const buySellRatio = sells > 0 ? buys / sells : buys > 0 ? 99 : 0;

  const metrics = {
    liquidityUsd: extractLiquidityUsd(pair),
    volume24hUsd: extractVolume24hUsd(pair),
    txns24hTotal: txns.total,
    buys24h: buys,
    sells24h: sells,
    buySellRatio,
    priceChange5m: priceChange.m5,
    priceChange1h: priceChange.h1,
    priceChange24h: priceChange.h24
  };

  metrics.prefilterScore = calculatePrefilterScore(metrics);

  const label = buildCleanDiscoveryLabel(pair, address);

  return {
    label,
    address,
    source: 'DISCOVERY',
    pairAddress: pair?.pairAddress,
    dex: pair?.dexId,
    dexUrl: pair?.url,
    prefilter: metrics
  };
}

function normalizeDiscoveredProfile(profile) {
  const chainId = profile?.chainId;
  const address = profile?.tokenAddress || profile?.address;

  if (chainId !== 'solana') {
    return null;
  }

  if (!address) {
    return null;
  }

  const label = buildCleanDiscoveryLabel(profile, address);

  return {
    label,
    address,
    source: 'DISCOVERY',
    prefilter: null
  };
}

async function discoverFromTokenProfiles() {
  try {
    const profiles = await getJson('https://api.dexscreener.com/token-profiles/latest/v1');

    if (!Array.isArray(profiles)) {
      return [];
    }

    return profiles.map(normalizeDiscoveredProfile).filter(Boolean);
  } catch (error) {
    console.log(`[DISCOVERY] token-profiles failed: ${error.message}`);
    return [];
  }
}

async function discoverFromBoostsLatest() {
  try {
    const boosts = await getJson('https://api.dexscreener.com/token-boosts/latest/v1');

    if (!Array.isArray(boosts)) {
      return [];
    }

    return boosts.map(normalizeDiscoveredProfile).filter(Boolean);
  } catch (error) {
    console.log(`[DISCOVERY] token-boosts latest failed: ${error.message}`);
    return [];
  }
}

async function discoverFromBoostsTop() {
  try {
    const boosts = await getJson('https://api.dexscreener.com/token-boosts/top/v1');

    if (!Array.isArray(boosts)) {
      return [];
    }

    return boosts.map(normalizeDiscoveredProfile).filter(Boolean);
  } catch (error) {
    console.log(`[DISCOVERY] token-boosts top failed: ${error.message}`);
    return [];
  }
}

async function discoverFromDexSearch(query) {
  try {
    const url = `https://api.dexscreener.com/latest/dex/search?q=${encodeURIComponent(query)}`;
    const data = await getJson(url);

    if (!Array.isArray(data?.pairs)) {
      return [];
    }

    return data.pairs.map(normalizeDiscoveredPair).filter(Boolean);
  } catch (error) {
    console.log(`[DISCOVERY] search "${query}" failed: ${error.message}`);
    return [];
  }
}

function shouldRejectByPrefilter(candidate) {
  const metrics = candidate.prefilter;

  if (!metrics) {
    return {
      rejected: false,
      reason: null
    };
  }

  if (metrics.liquidityUsd < DISCOVERY_PREFILTER.minLiquidityUsd) {
    return {
      rejected: true,
      reason: `liquidity_below_${DISCOVERY_PREFILTER.minLiquidityUsd}`
    };
  }

  if (metrics.volume24hUsd < DISCOVERY_PREFILTER.minVolume24hUsd) {
    return {
      rejected: true,
      reason: `volume24h_below_${DISCOVERY_PREFILTER.minVolume24hUsd}`
    };
  }

  if (metrics.txns24hTotal < DISCOVERY_PREFILTER.minTxns24h) {
    return {
      rejected: true,
      reason: `txns24h_below_${DISCOVERY_PREFILTER.minTxns24h}`
    };
  }

  if (metrics.buySellRatio < DISCOVERY_PREFILTER.minBuySellRatio) {
    return {
      rejected: true,
      reason: `buy_sell_ratio_below_${DISCOVERY_PREFILTER.minBuySellRatio}`
    };
  }

  return {
    rejected: false,
    reason: null
  };
}

function dedupeCandidates(candidates) {
  const byAddress = new Map();

  const officialAddresses = new Set(OFFICIAL_WATCHLIST.map((item) => item.address));

  for (const candidate of candidates) {
    if (!candidate?.address) {
      continue;
    }

    if (officialAddresses.has(candidate.address)) {
      continue;
    }

    if (blockedMemory.has(candidate.address)) {
      continue;
    }

    if (skippedMemory.has(candidate.address)) {
      continue;
    }

    if (prefilterRejectedMemory.has(candidate.address)) {
      continue;
    }

    if (!byAddress.has(candidate.address)) {
      byAddress.set(candidate.address, candidate);
      continue;
    }

    const existing = byAddress.get(candidate.address);
    const existingScore = existing?.prefilter?.prefilterScore || 0;
    const candidateScore = candidate?.prefilter?.prefilterScore || 0;

    if (candidateScore > existingScore) {
      byAddress.set(candidate.address, candidate);
    }
  }

  return Array.from(byAddress.values());
}

function applyDiscoveryPrefilter(candidates) {
  const passed = [];
  const rejected = [];

  for (const candidate of candidates) {
    const result = shouldRejectByPrefilter(candidate);

    if (result.rejected) {
      candidate.prefilter = candidate.prefilter || {};
      candidate.prefilter.rejectReason = result.reason;
      prefilterRejectedMemory.add(candidate.address);
      savePrefilterRejectedToVault(candidate);
      rejected.push(candidate);
      continue;
    }

    passed.push(candidate);
  }

  return {
    passed,
    rejected
  };
}

async function discoverCandidates() {
  console.log('');
  console.log('--------------------------------------------------');
  console.log('[DISCOVERY] Searching for new Solana candidates...');
  console.log('--------------------------------------------------');

  const allCandidates = [
    ...(await discoverFromDexSearch('pump')),
    ...(await discoverFromDexSearch('solana')),
    ...(await discoverFromDexSearch('meme')),
    ...(await discoverFromTokenProfiles()),
    ...(await discoverFromBoostsLatest()),
    ...(await discoverFromBoostsTop())
  ];

  const deduped = dedupeCandidates(allCandidates);
  const { passed, rejected } = applyDiscoveryPrefilter(deduped);

  const sortedPassed = passed
    .slice()
    .sort((a, b) => (b?.prefilter?.prefilterScore || 0) - (a?.prefilter?.prefilterScore || 0));

  const limited = sortedPassed.slice(0, DISCOVERY_PREFILTER.maxDiscoveryPerLoop);

  for (const candidate of limited) {
    const now = new Date().toISOString();
    const previous = discoveredTokens.get(candidate.address);

    discoveredTokens.set(candidate.address, {
      ...candidate,
      firstSeenAt: previous?.firstSeenAt || now,
      lastSeenAt: now
    });

    upsertVaultRecord(
      VAULT_FILES.discoveryCandidates,
      {
        label: candidate.label,
        source: candidate.source,
        status: 'DISCOVERED_PREFILTER_PASSED',
        address: candidate.address,
        tokenAddress: candidate.address,
        pairAddress: candidate.pairAddress || null,
        dex: candidate.dex || null,
        dexUrl: candidate.dexUrl || null,
        prefilter: candidate.prefilter || null,
        opportunityScore: candidate?.prefilter?.prefilterScore || 0
      },
      {
        sortByOpportunity: true,
        maxRecords: 5000
      }
    );
  }

  console.log(`[DISCOVERY] Raw candidates: ${allCandidates.length}`);
  console.log(`[DISCOVERY] Deduped candidates: ${deduped.length}`);
  console.log(`[DISCOVERY] Prefilter passed: ${passed.length}`);
  console.log(`[DISCOVERY] Prefilter rejected: ${rejected.length}`);
  console.log(`[DISCOVERY] Selected for ShieldAPI: ${limited.length}`);

  if (rejected.length > 0) {
    console.log('');
    console.log('================ PREFILTER REJECTED SAMPLE ================');

    for (const item of rejected.slice(0, 5)) {
      printPrefilterRejected(item);
    }
  }

  return limited;
}

function buildLoopSummary(results) {
  const valid = results.filter(Boolean);

  const official = valid.filter(
    (result) => result.item.source === 'OFFICIAL' || result.item.source === 'TEST_BLOCKED'
  );
  const discovery = valid.filter((result) => result.item.source === 'DISCOVERY');

  const officialApproved = official.filter((result) => result.statusType === 'APPROVED');
  const officialBlocked = official.filter((result) => result.statusType === 'BLOCKED');
  const officialWarnings = official.filter((result) => result.statusType === 'WARNING');
  const officialErrors = official.filter((result) => result.statusType === 'ERROR');

  const discoveryApproved = discovery.filter((result) => result.statusType === 'APPROVED');
  const discoveryWarnings = discovery.filter((result) => result.statusType === 'WARNING');
  const discoveryBlocked = discovery.filter((result) => result.statusType === 'BLOCKED');
  const discoverySkipped = discovery.filter((result) => result.statusType === 'SKIPPED');
  const discoveryErrors = discovery.filter((result) => result.statusType === 'ERROR');

  const strongestDiscovery = discoveryApproved
    .slice()
    .sort((a, b) => b.opportunityScore - a.opportunityScore)
    .slice(0, 5)
    .map((result) => ({
      label: result.item.label,
      address: result.item.address,
      tokenAddress: result.data?.tokenAddress || result.item.address,
      pairAddress: result.data?.pairAddress || result.item.pairAddress || null,
      opportunityScore: result.opportunityScore,
      riskLevel: result.data?.riskLevel || 'UNKNOWN',
      riskScore: Number(result.data?.riskScore || 0),
      liquidity: Number(result.data?.liquidity || 0),
      volume24h: Number(result.data?.volume24h || 0),
      dex: result.data?.dex || result.item.dex || null,
      dexUrl: result.data?.dexUrl || result.item.dexUrl || null
    }));

  return {
    version: '3.3.2',
    name: 'ScannerAgent Candidate Vault',
    lastLoopAt: new Date().toISOString(),
    official: {
      total: official.length,
      approved: officialApproved.length,
      warnings: officialWarnings.length,
      blocked: officialBlocked.length,
      errors: officialErrors.length
    },
    discovery: {
      total: discovery.length,
      approved: discoveryApproved.length,
      warnings: discoveryWarnings.length,
      blocked: discoveryBlocked.length,
      skipped: discoverySkipped.length,
      errors: discoveryErrors.length
    },
    memory: {
      discoveredTokens: discoveredTokens.size,
      blockedTokens: blockedMemory.size,
      skippedTokens: skippedMemory.size,
      prefilterRejected: prefilterRejectedMemory.size
    },
    strongestDiscovery
  };
}

function saveLoopSummary(summary) {
  const previous = readJsonFile(VAULT_FILES.scannerSummary, {});
  const loopCount = Number(previous.loopCount || 0) + 1;

  writeJsonFile(VAULT_FILES.scannerSummary, {
    ...summary,
    loopCount
  });
}

function printLoopSummary(results) {
  const summary = buildLoopSummary(results);
  saveLoopSummary(summary);

  console.log('');
  console.log('================ LOOP SUMMARY ================');
  console.log(`Official approved:      ${summary.official.approved}`);
  console.log(`Official warnings:      ${summary.official.warnings}`);
  console.log(`Official blocked/test:  ${summary.official.blocked}`);
  console.log(`Official errors:        ${summary.official.errors}`);
  console.log('--------------------------------------------------');
  console.log(`Discovery approved:     ${summary.discovery.approved}`);
  console.log(`Discovery warnings:     ${summary.discovery.warnings}`);
  console.log(`Discovery blocked:      ${summary.discovery.blocked}`);
  console.log(`Discovery skipped:      ${summary.discovery.skipped}`);
  console.log(`Discovery errors:       ${summary.discovery.errors}`);
  console.log(`Discovery memory:       ${summary.memory.discoveredTokens}`);
  console.log(`Blocked memory:         ${summary.memory.blockedTokens}`);
  console.log(`Skipped memory:         ${summary.memory.skippedTokens}`);
  console.log(`Prefilter memory:       ${summary.memory.prefilterRejected}`);
  console.log('--------------------------------------------------');

  if (summary.strongestDiscovery.length === 0) {
    console.log('Top discovery candidates: none');
  } else {
    console.log('Top discovery candidates:');

    for (const result of summary.strongestDiscovery) {
      console.log(
        `- ${result.label} | opp=${result.opportunityScore}/100 | liq=$${Number(
          result.liquidity || 0
        ).toLocaleString('en-US')} | vol24h=$${Number(result.volume24h || 0).toLocaleString(
          'en-US'
        )} | ${result.dexUrl}`
      );
    }
  }

  console.log('--------------------------------------------------');
  console.log(`[VAULT] Saved summary: ${VAULT_FILES.scannerSummary}`);
  console.log('==============================================');
}

async function runScanner() {
  ensureVaultFiles();
  loadVaultMemories();

  console.log('==============================================');
  console.log(' ShieldAPI AI Agent / Frequency Scanner v3.3.2');
  console.log(' Candidate Vault Enabled');
  console.log('==============================================');
  console.log(`ShieldAPI URL: ${SHIELD_API_URL}`);
  console.log(`Official watchlist: ${OFFICIAL_WATCHLIST.map((item) => item.label).join(', ')}`);
  console.log(`Interval: ${SCAN_INTERVAL_MS / 1000} seconds`);
  console.log(`Discovery limit: ${DISCOVERY_PREFILTER.maxDiscoveryPerLoop}`);
  console.log(`Discovery min liquidity: $${DISCOVERY_PREFILTER.minLiquidityUsd.toLocaleString('en-US')}`);
  console.log(`Discovery min volume 24h: $${DISCOVERY_PREFILTER.minVolume24hUsd.toLocaleString('en-US')}`);
  console.log(`Discovery min txns 24h: ${DISCOVERY_PREFILTER.minTxns24h}`);
  console.log(`Vault folder: ${DATA_DIR}`);
  console.log('Mode: smart discovery filter + persistent candidate vault');
  console.log('==============================================');

  while (true) {
    const loopResults = [];

    console.log('');
    console.log(`[LOOP] New scan started at ${new Date().toISOString()}`);

    console.log('');
    console.log('================ OFFICIAL WATCHLIST ================');

    for (const item of OFFICIAL_WATCHLIST) {
      const result = await scanToken(item);
      loopResults.push(result);
      await sleep(1500);
    }

    const discovered = await discoverCandidates();

    if (discovered.length > 0) {
      console.log('');
      console.log('================ DISCOVERY CANDIDATES ================');

      for (const item of discovered) {
        const result = await scanToken(item);
        loopResults.push(result);
        await sleep(DISCOVERY_SCAN_DELAY_MS);
      }
    } else {
      console.log('');
      console.log('[DISCOVERY] No candidates passed prefilter in this loop.');
    }

    printLoopSummary(loopResults);

    console.log('');
    console.log(`[LOOP] Scan finished. Waiting ${SCAN_INTERVAL_MS / 1000} seconds...`);

    await sleep(SCAN_INTERVAL_MS);
  }
}

runScanner().catch((error) => {
  console.error('[FATAL] Scanner crashed:', error);
  process.exit(1);
});
