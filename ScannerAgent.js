import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VERSION = '3.4.0';

const SHIELD_API_URL =
  process.env.SHIELD_API_URL || 'https://zucchini-caring-production.up.railway.app';

// For now we keep the fallback key so the scanner does not break.
// Later, rotate this key and use only process.env.SHIELD_API_KEY.
const SHIELD_API_KEY =
  process.env.SHIELD_API_KEY || 'shield_prod_2026_9xK72pQ';

const SCAN_INTERVAL_MS = Number(process.env.SCAN_INTERVAL_MS || 60_000);
const DISCOVERY_SCAN_DELAY_MS = Number(process.env.DISCOVERY_SCAN_DELAY_MS || 1200);

const USE_ANALYZE_FAST_FIRST =
  String(process.env.USE_ANALYZE_FAST_FIRST || 'true').toLowerCase() !== 'false';

const TG_BOT_TOKEN =
  process.env.TG_BOT_TOKEN || process.env.TELEGRAM_BOT_TOKEN || '';

const TG_CHAT_ID =
  process.env.TG_CHAT_ID || process.env.TELEGRAM_CHAT_ID || '';

const TELEGRAM_ENABLED =
  String(process.env.TELEGRAM_ENABLED || 'true').toLowerCase() !== 'false' &&
  Boolean(TG_BOT_TOKEN) &&
  Boolean(TG_CHAT_ID);

const TELEGRAM_MIN_OPPORTUNITY_SCORE = Number(process.env.TELEGRAM_MIN_OPPORTUNITY_SCORE || 80);
const TELEGRAM_ALERT_DEDUP_TTL_MS = Number(process.env.TELEGRAM_ALERT_DEDUP_TTL_MS || 30 * 60 * 1000);
const TELEGRAM_SEND_DELAY_MS = Number(process.env.TELEGRAM_SEND_DELAY_MS || 600);

const DISCOVERY_PREFILTER = {
  minLiquidityUsd: Number(process.env.DISCOVERY_MIN_LIQUIDITY_USD || 20_000),
  minVolume24hUsd: Number(process.env.DISCOVERY_MIN_VOLUME_24H_USD || 50_000),
  minTxns24h: Number(process.env.DISCOVERY_MIN_TXNS_24H || 300),
  minBuySellRatio: Number(process.env.DISCOVERY_MIN_BUY_SELL_RATIO || 0.9),
  maxDiscoveryPerLoop: Number(process.env.DISCOVERY_MAX_PER_LOOP || 12)
};

const DATA_DIR = path.join(__dirname, 'data');

const VAULT_FILES = {
  discoveryCandidates: path.join(DATA_DIR, 'discovery_candidates.json'),
  approvedCandidates: path.join(DATA_DIR, 'approved_candidates.json'),
  blockedTokens: path.join(DATA_DIR, 'blocked_tokens.json'),
  skippedTokens: path.join(DATA_DIR, 'skipped_tokens.json'),
  prefilterRejected: path.join(DATA_DIR, 'prefilter_rejected_tokens.json'),
  errors: path.join(DATA_DIR, 'scanner_errors.json'),
  telegramAlerts: path.join(DATA_DIR, 'telegram_alerts.json'),
  scannerSummary: path.join(DATA_DIR, 'scanner_summary.json')
};

const OFFICIAL_WATCHLIST = [
  { label: 'BONK', address: 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263', source: 'OFFICIAL' },
  { label: 'WIF', address: 'EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm', source: 'OFFICIAL' },
  { label: 'POPCAT', address: '7GCihgDB8fe6KNjn2MYtkzZcRjQy3t9GHdC8uHYmW2hr', source: 'OFFICIAL' },
  { label: 'MEW', address: 'MEW1gQWJ3nEXg2qgERiKu7FAFj79PHvQVREQUzScPP5', source: 'OFFICIAL' },
  { label: 'MYRO', address: 'HhJpBhRRn4g56VsyLuT8DL5Bv31HkXqsrahTTUCZeZg4', source: 'OFFICIAL' },
  { label: 'BOME', address: 'ukHH6c7mMyiWCf1b9pnWe25TSpkDDt3H5pQZgZ74J82', source: 'OFFICIAL' },
  { label: 'SLERF', address: '9999FVbjHioTcoJpoBiSjpxHW6xEn3witVuXKqBh2RFQ', source: 'OFFICIAL' },
  { label: 'WATERCOIN_TEST', address: '9RFDHRx92t1SNM5Cd7kz3oQK1EmxdvEb3ZtRheFWpump', source: 'TEST_BLOCKED' }
];

const history = new Map();
const discoveredTokens = new Map();
const blockedMemory = new Set();
const skippedMemory = new Set();
const prefilterRejectedMemory = new Set();
const telegramAlertMemory = new Map();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function shortAddress(address) {
  if (!address || typeof address !== 'string') return 'UNKNOWN';
  if (address.length <= 12) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function numberValue(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function fmtUsd(value) {
  return `$${numberValue(value).toLocaleString('en-US', { maximumFractionDigits: 2 })}`;
}

function fmtPct(value) {
  return `${numberValue(value).toFixed(2)}%`;
}

function readJsonFile(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw.trim()) return fallback;
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

function ensureVaultFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

  const arrayFiles = [
    VAULT_FILES.discoveryCandidates,
    VAULT_FILES.approvedCandidates,
    VAULT_FILES.blockedTokens,
    VAULT_FILES.skippedTokens,
    VAULT_FILES.prefilterRejected,
    VAULT_FILES.errors,
    VAULT_FILES.telegramAlerts
  ];

  for (const file of arrayFiles) {
    if (!fs.existsSync(file)) writeJsonFile(file, []);
  }

  if (!fs.existsSync(VAULT_FILES.scannerSummary)) {
    writeJsonFile(VAULT_FILES.scannerSummary, {
      version: VERSION,
      name: 'ScannerAgent Telegram Alerts',
      createdAt: new Date().toISOString(),
      lastLoopAt: null,
      loopCount: 0
    });
  }
}

function getRecordKey(record) {
  return record?.tokenAddress || record?.address || record?.pairAddress || record?.dexUrl || record?.label || null;
}

function upsertVaultRecord(file, record, options = {}) {
  const { sortByOpportunity = false, maxRecords = 5000 } = options;
  const now = new Date().toISOString();
  const rows = readJsonFile(file, []);
  const key = getRecordKey(record);
  if (!key) return;

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
    finalRows = rows.slice().sort((a, b) => Number(b.opportunityScore || 0) - Number(a.opportunityScore || 0));
  }

  if (finalRows.length > maxRecords) finalRows = finalRows.slice(0, maxRecords);

  writeJsonFile(file, finalRows);
}

function appendVaultRecord(file, record, options = {}) {
  const { maxRecords = 5000 } = options;
  const rows = readJsonFile(file, []);
  rows.unshift({
    ...record,
    createdAt: new Date().toISOString()
  });
  writeJsonFile(file, rows.slice(0, maxRecords));
}

function loadVaultMemories() {
  const blockedRows = readJsonFile(VAULT_FILES.blockedTokens, []);
  const skippedRows = readJsonFile(VAULT_FILES.skippedTokens, []);
  const rejectedRows = readJsonFile(VAULT_FILES.prefilterRejected, []);
  const discoveryRows = readJsonFile(VAULT_FILES.discoveryCandidates, []);
  const telegramRows = readJsonFile(VAULT_FILES.telegramAlerts, []);

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
    if (key) discoveredTokens.set(key, row);
  }

  for (const row of telegramRows) {
    if (!row.alertKey || !row.sentAtMs) continue;
    const ageMs = Date.now() - Number(row.sentAtMs || 0);
    if (ageMs <= TELEGRAM_ALERT_DEDUP_TTL_MS) {
      telegramAlertMemory.set(row.alertKey, Number(row.sentAtMs));
    }
  }

  console.log(`[VAULT] Loaded blocked memory: ${blockedMemory.size}`);
  console.log(`[VAULT] Loaded skipped memory: ${skippedMemory.size}`);
  console.log(`[VAULT] Loaded prefilter memory: ${prefilterRejectedMemory.size}`);
  console.log(`[VAULT] Loaded discovery memory: ${discoveredTokens.size}`);
  console.log(`[VAULT] Loaded telegram alert memory: ${telegramAlertMemory.size}`);
}

function cleanupTelegramAlertMemory() {
  const now = Date.now();
  for (const [key, sentAtMs] of telegramAlertMemory.entries()) {
    if (now - sentAtMs > TELEGRAM_ALERT_DEDUP_TTL_MS) {
      telegramAlertMemory.delete(key);
    }
  }
}

function buildAnalyzeUrl(item, mode = 'deep') {
  const endpoint = mode === 'fast' ? '/analyze-fast' : '/analyze';
  const base = `${SHIELD_API_URL}${endpoint}`;
  return `${base}?address=${encodeURIComponent(item.address)}&key=${encodeURIComponent(SHIELD_API_KEY)}`;
}

async function fetchShieldAPI(item, mode = 'deep') {
  const url = buildAnalyzeUrl(item, mode);

  const response = await fetch(url, {
    headers: { accept: 'application/json' }
  });

  const text = await response.text();
  let parsed;

  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }

  return {
    ok: response.ok,
    statusCode: response.status,
    payload: parsed,
    rawText: text,
    mode
  };
}

async function callShieldAPI(item) {
  if (USE_ANALYZE_FAST_FIRST) {
    const fastResult = await fetchShieldAPI(item, 'fast');
    const fastPayload = fastResult.payload || {};

    if (
      fastResult.ok &&
      fastPayload.status &&
      fastPayload.status !== 'UNKNOWN' &&
      fastPayload.status !== 'ERROR'
    ) {
      return {
        ...fastPayload,
        scannerApiMode: 'fast'
      };
    }

    const shouldFallbackToDeep =
      fastResult.statusCode === 404 ||
      fastPayload.status === 'UNKNOWN' ||
      String(fastPayload.reason || '').includes('Token not in cache');

    if (!shouldFallbackToDeep && (fastResult.statusCode === 401 || fastResult.statusCode === 403)) {
      const error = new Error(fastPayload.reason || 'API key invalid or forbidden');
      error.httpStatus = fastResult.statusCode;
      error.payload = fastPayload;
      throw error;
    }
  }

  const deepResult = await fetchShieldAPI(item, 'deep');
  const deepPayload = deepResult.payload || {};

  if (!deepResult.ok) {
    const reason = deepPayload?.reason || deepPayload?.error || deepResult.rawText || 'Unknown API error';
    const error = new Error(reason);
    error.httpStatus = deepResult.statusCode;
    error.payload = deepPayload;
    throw error;
  }

  return {
    ...deepPayload,
    scannerApiMode: 'deep'
  };
}

function isImageUrl(value) {
  if (!value || typeof value !== 'string') return false;
  return (
    value.startsWith('http://') ||
    value.startsWith('https://') ||
    value.includes('cdn.dexscreener.com') ||
    value.includes('/images/') ||
    value.includes('format=auto')
  );
}

function cleanText(value) {
  if (!value || typeof value !== 'string') return '';

  const cleaned = value
    .replace(/\s+/g, ' ')
    .replace(/[^\x20-\x7E]/g, '')
    .trim();

  if (!cleaned || isImageUrl(cleaned)) return '';
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
    if (cleaned && cleaned.length <= 40) return cleaned;
  }

  return shortAddress(address);
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
  return { buys, sells, total: buys + sells };
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
  const response = await fetch(url, { headers: { accept: 'application/json' } });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP ${response.status}: ${text}`);
  }

  return response.json();
}

function getPreviousSnapshot(label) {
  const snapshots = history.get(label) || [];
  if (snapshots.length === 0) return null;
  return snapshots[snapshots.length - 1];
}

function createSnapshotFromData(data) {
  return {
    status: data.status,
    riskScore: numberValue(data.riskScore),
    riskLevel: data.riskLevel || 'UNKNOWN',
    price: numberValue(data.price),
    liquidity: numberValue(data.liquidity),
    volume24h: numberValue(data.volume24h),
    txns24hTotal: numberValue(data?.txns24h?.total),
    buys24h: numberValue(data?.txns24h?.buys),
    sells24h: numberValue(data?.txns24h?.sells),
    priceChange5m: numberValue(data?.priceChange?.m5),
    priceChange1h: numberValue(data?.priceChange?.h1),
    priceChange24h: numberValue(data?.priceChange?.h24),
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
  snapshots.push({ ...snapshot, timestamp: Date.now() });
  if (snapshots.length > 30) snapshots.shift();
  history.set(label, snapshots);
}

function calculateChange(current, previous, field) {
  const currentValue = numberValue(current[field]);
  const previousValue = numberValue(previous[field]);
  if (previousValue <= 0) return 0;
  return ((currentValue - previousValue) / previousValue) * 100;
}

function calculateOpportunityScore(current, previous) {
  let score = 0;

  const buys24h = numberValue(current.buys24h);
  const sells24h = numberValue(current.sells24h);
  const buySellRatio = sells24h > 0 ? buys24h / sells24h : buys24h > 0 ? 99 : 0;

  if (current.status === 'APPROVED') score += 25;
  if (current.riskLevel === 'LOW') score += 20;

  if (current.liquidity >= 250000) score += 20;
  else if (current.liquidity >= 100000) score += 16;
  else if (current.liquidity >= 50000) score += 12;
  else if (current.liquidity >= 25000) score += 8;

  if (current.volume24h >= 1000000) score += 18;
  else if (current.volume24h >= 250000) score += 14;
  else if (current.volume24h >= 100000) score += 10;
  else if (current.volume24h >= 50000) score += 6;

  if (current.txns24hTotal >= 10000) score += 12;
  else if (current.txns24hTotal >= 2000) score += 10;
  else if (current.txns24hTotal >= 500) score += 6;

  if (buySellRatio >= 1.25) score += 12;
  else if (buySellRatio >= 1.05) score += 8;
  else if (buySellRatio >= 0.9) score += 3;

  if (current.priceChange5m > 0) score += 4;
  if (current.priceChange1h > 0) score += 4;

  if (previous) {
    const volumeChangePct = calculateChange(current, previous, 'volume24h');
    const txnsChangePct = calculateChange(current, previous, 'txns24hTotal');
    if (volumeChangePct >= 15) score += 10;
    if (txnsChangePct >= 15) score += 10;
  }

  if (buySellRatio < 0.15) score -= 60;
  else if (buySellRatio < 0.25) score -= 45;
  else if (buySellRatio < 0.5) score -= 30;
  else if (buySellRatio < 0.75) score -= 15;
  else if (buySellRatio < 0.9) score -= 8;

  if (current.priceChange5m <= -10) score -= 12;
  else if (current.priceChange5m <= -5) score -= 6;

  if (current.priceChange1h <= -20) score -= 12;
  else if (current.priceChange1h <= -10) score -= 6;

  score = Math.max(0, Math.min(score, 100));

  if (buySellRatio < 0.15) score = Math.min(score, 25);
  else if (buySellRatio < 0.25) score = Math.min(score, 35);
  else if (buySellRatio < 0.5) score = Math.min(score, 50);
  else if (buySellRatio < 0.75) score = Math.min(score, 65);

  return score;
}

function calculatePrefilterScore(metrics) {
  let score = 0;

  if (metrics.liquidityUsd >= 50000) score += 30;
  else if (metrics.liquidityUsd >= 30000) score += 20;
  else if (metrics.liquidityUsd >= 20000) score += 10;

  if (metrics.volume24hUsd >= 250000) score += 25;
  else if (metrics.volume24hUsd >= 100000) score += 20;
  else if (metrics.volume24hUsd >= 50000) score += 10;

  if (metrics.txns24hTotal >= 5000) score += 20;
  else if (metrics.txns24hTotal >= 1000) score += 15;
  else if (metrics.txns24hTotal >= 300) score += 10;

  if (metrics.buySellRatio >= 1.2) score += 15;
  else if (metrics.buySellRatio >= 1.0) score += 10;
  else if (metrics.buySellRatio >= 0.9) score += 5;

  if (metrics.priceChange5m > 0) score += 5;
  if (metrics.priceChange1h > 0) score += 5;

  return Math.min(score, 100);
}

function analyzeFrequency(label, current, previous, source) {
  const alerts = [];
  const opportunityScore = calculateOpportunityScore(current, previous);

  const buys24h = numberValue(current.buys24h);
  const sells24h = numberValue(current.sells24h);
  const buySellRatio = sells24h > 0 ? buys24h / sells24h : buys24h > 0 ? 99 : 0;

  if (current.status === 'BLOCKED') {
    alerts.push({
      level: 'BLOCKED',
      message: `${label} is blocked by ShieldAPI. Risk level: ${current.riskLevel}. Risk score: ${current.riskScore}.`
    });
    return { alerts, opportunityScore };
  }

  if (current.status === 'WARNING') {
    alerts.push({ level: 'WARNING', message: `${label} has medium risk. Manual review recommended.` });
  }

  if (sells24h > 0 && buySellRatio < 0.5) {
    alerts.push({
      level: 'SELL_PRESSURE',
      message: `${label} has strong sell pressure: buys/sells ratio ${buySellRatio.toFixed(2)} (${buys24h}/${sells24h}). Opportunity score was penalized.`
    });
  }

  if (!previous) {
    if (current.status === 'APPROVED') {
      alerts.push({ level: 'FIRST_SCAN', message: `${label} approved on first scan. Waiting for history to detect frequency changes.` });
    }

    if (source === 'DISCOVERY' && current.status === 'APPROVED') {
      alerts.push({ level: 'NEW_DISCOVERY', message: `${label} discovered automatically and passed ShieldAPI. Opportunity score: ${opportunityScore}/100.` });
    }

    return { alerts, opportunityScore };
  }

  const volumeChangePct = calculateChange(current, previous, 'volume24h');
  const txnsChangePct = calculateChange(current, previous, 'txns24hTotal');
  const liquidityChangePct = calculateChange(current, previous, 'liquidity');

  if (volumeChangePct >= 25) {
    alerts.push({ level: 'VOLUME_SPIKE', message: `${label} volume increased ${volumeChangePct.toFixed(2)}% since last scan.` });
  }

  if (txnsChangePct >= 25) {
    alerts.push({ level: 'TXNS_SPIKE', message: `${label} transaction activity increased ${txnsChangePct.toFixed(2)}% since last scan.` });
  }

  if (liquidityChangePct <= -20) {
    alerts.push({ level: 'LIQUIDITY_DROP', message: `${label} liquidity dropped ${Math.abs(liquidityChangePct).toFixed(2)}% since last scan.` });
  }

  if (current.priceChange5m >= 5 && current.txns24hTotal > previous.txns24hTotal) {
    alerts.push({ level: 'MOMENTUM', message: `${label} shows short-term momentum: 5m price change ${current.priceChange5m}%.` });
  }

  if (
    current.status === 'APPROVED' &&
    current.riskLevel === 'LOW' &&
    volumeChangePct >= 15 &&
    txnsChangePct >= 15
  ) {
    alerts.push({ level: 'AI_AGENT_SIGNAL', message: `${label} is heating up with low risk, rising volume and rising transaction frequency. Opportunity score: ${opportunityScore}/100.` });
  }

  if (source === 'DISCOVERY' && current.status === 'APPROVED' && opportunityScore >= 70) {
    alerts.push({ level: 'DISCOVERY_CANDIDATE', message: `${label} is a strong discovered candidate. Opportunity score: ${opportunityScore}/100.` });
  }

  if (alerts.length === 0) {
    alerts.push({ level: 'NORMAL', message: `${label} has no abnormal frequency signal in this scan.` });
  }

  return { alerts, opportunityScore };
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
    riskScore: numberValue(data.riskScore),
    opportunityScore: numberValue(result.opportunityScore),

    address: item.address,
    tokenAddress: data.tokenAddress || item.address,
    pairAddress: data.pairAddress || item.pairAddress || null,

    tokenName: data.tokenName || null,
    tokenSymbol: data.tokenSymbol || item.label || null,

    price: numberValue(data.price),
    liquidity: numberValue(data.liquidity),
    volume24h: numberValue(data.volume24h),

    txns24h: {
      buys: numberValue(txns24h.buys),
      sells: numberValue(txns24h.sells),
      total: numberValue(txns24h.total)
    },

    priceChange: {
      m5: numberValue(data?.priceChange?.m5),
      h1: numberValue(data?.priceChange?.h1),
      h6: numberValue(data?.priceChange?.h6),
      h24: numberValue(data?.priceChange?.h24)
    },

    dex: data.dex || item.dex || null,
    dexUrl: data.dexUrl || item.dexUrl || null,

    apiMode: data.scannerApiMode || data.mode || null,
    cacheHit: data.cacheHit === true,
    dataAgeSeconds: numberValue(data.dataAgeSeconds),
    apiResponseTimeMs: numberValue(data.responseTimeMs),

    prefilter: item.prefilter || null,

    alerts: alerts.map((alert) => ({ level: alert.level, message: alert.message }))
  };
}

function saveScanResultToVault(result) {
  if (!result || !result.item) return;

  const record = buildVaultRecord(result);

  if (result.item.source === 'DISCOVERY') {
    upsertVaultRecord(VAULT_FILES.discoveryCandidates, record, { sortByOpportunity: true, maxRecords: 5000 });
  }

  if (result.statusType === 'APPROVED') {
    upsertVaultRecord(VAULT_FILES.approvedCandidates, record, { sortByOpportunity: true, maxRecords: 3000 });
  }

  if (result.statusType === 'BLOCKED') {
    upsertVaultRecord(VAULT_FILES.blockedTokens, record, { maxRecords: 5000 });
  }

  if (result.statusType === 'SKIPPED') {
    upsertVaultRecord(VAULT_FILES.skippedTokens, record, { maxRecords: 5000 });
  }

  if (result.statusType === 'ERROR') {
    upsertVaultRecord(VAULT_FILES.errors, record, { maxRecords: 3000 });
  }
}

function savePrefilterRejectedToVault(item) {
  upsertVaultRecord(
    VAULT_FILES.prefilterRejected,
    {
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
    },
    { maxRecords: 5000 }
  );
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
    { maxRecords: 3000 }
  );
}

function escapeTelegramHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function getImportantTelegramAlerts(result) {
  const important = [];
  const alerts = result.alerts || [];
  const data = result.data || {};
  const source = result.item?.source || 'UNKNOWN';
  const score = numberValue(result.opportunityScore);
  const riskScore = numberValue(data.riskScore);

  if (result.statusType === 'APPROVED' && source === 'DISCOVERY' && score >= TELEGRAM_MIN_OPPORTUNITY_SCORE) {
    important.push({ level: 'APPROVED_HIGH_SCORE', message: `Approved discovery candidate with opportunity score ${score}/100.` });
  }

  for (const alert of alerts) {
    if (
      alert.level === 'DISCOVERY_CANDIDATE' ||
      alert.level === 'AI_AGENT_SIGNAL' ||
      alert.level === 'SELL_PRESSURE' ||
      alert.level === 'LIQUIDITY_DROP' ||
      alert.level === 'VOLUME_SPIKE' ||
      alert.level === 'TXNS_SPIKE'
    ) {
      important.push(alert);
    }
  }

  if (result.statusType === 'BLOCKED' && riskScore >= 40) {
    important.push({ level: 'BLOCKED_HIGH_RISK', message: `Token blocked. Risk level ${data.riskLevel || 'UNKNOWN'} / score ${riskScore}.` });
  }

  if (result.statusType === 'ERROR') {
    important.push({ level: 'SCANNER_ERROR', message: alerts[0]?.message || 'Scanner error.' });
  }

  const unique = [];
  const seen = new Set();

  for (const alert of important) {
    const key = `${alert.level}:${alert.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(alert);
  }

  return unique;
}

function buildTelegramAlertKey(result, alert) {
  const tokenKey = result.data?.tokenAddress || result.item?.address || result.item?.label || 'unknown';
  return `${alert.level}:${tokenKey}`;
}

function shouldSendTelegramAlert(result, alert) {
  cleanupTelegramAlertMemory();

  const alertKey = buildTelegramAlertKey(result, alert);
  const lastSentAt = telegramAlertMemory.get(alertKey);
  const now = Date.now();

  if (lastSentAt && now - lastSentAt < TELEGRAM_ALERT_DEDUP_TTL_MS) {
    return { send: false, alertKey, reason: 'dedup_ttl' };
  }

  return { send: true, alertKey, reason: 'ok' };
}

function buildTelegramMessage(result, alert) {
  const item = result.item || {};
  const data = result.data || {};
  const label = data.tokenSymbol || item.label || shortAddress(item.address);
  const score = numberValue(result.opportunityScore);
  const buys = numberValue(data?.txns24h?.buys);
  const sells = numberValue(data?.txns24h?.sells);
  const buySellRatio = sells > 0 ? buys / sells : buys > 0 ? 99 : 0;
  const apiMode = data.scannerApiMode || data.mode || 'unknown';
  const cacheHit = data.cacheHit === true ? 'true' : 'false';
  const apiTime = data.responseTimeMs ?? 'n/a';

  const titleEmoji =
    alert.level.includes('BLOCKED') ? '🚫' :
    alert.level.includes('SELL') ? '⚠️' :
    alert.level.includes('LIQUIDITY') ? '💧' :
    alert.level.includes('ERROR') ? '❌' :
    '🚀';

  const lines = [
    `${titleEmoji} <b>ShieldAPI Alert</b>`,
    '',
    `<b>${escapeTelegramHtml(alert.level)}</b>`,
    escapeTelegramHtml(alert.message),
    '',
    `<b>Token:</b> ${escapeTelegramHtml(label)}`,
    `<b>Status:</b> ${escapeTelegramHtml(result.statusType || data.status || 'UNKNOWN')}`,
    `<b>Risk:</b> ${escapeTelegramHtml(data.riskLevel || 'UNKNOWN')} / ${escapeTelegramHtml(data.riskScore ?? 'n/a')}`,
    `<b>Opportunity:</b> ${score}/100`,
    `<b>Liquidity:</b> ${escapeTelegramHtml(fmtUsd(data.liquidity))}`,
    `<b>Volume 24h:</b> ${escapeTelegramHtml(fmtUsd(data.volume24h))}`,
    `<b>Txns 24h:</b> ${numberValue(data?.txns24h?.total).toLocaleString('en-US')}`,
    `<b>Buys/Sells:</b> ${buys}/${sells} (${buySellRatio.toFixed(2)})`,
    `<b>Price 5m/1h/24h:</b> ${escapeTelegramHtml(fmtPct(data?.priceChange?.m5))} / ${escapeTelegramHtml(fmtPct(data?.priceChange?.h1))} / ${escapeTelegramHtml(fmtPct(data?.priceChange?.h24))}`,
    `<b>DEX:</b> ${escapeTelegramHtml(data.dex || item.dex || 'n/a')}`,
    `<b>API:</b> ${escapeTelegramHtml(apiMode)} | cache=${cacheHit} | ${escapeTelegramHtml(apiTime)}ms`,
    '',
    `<b>Token:</b> <code>${escapeTelegramHtml(data.tokenAddress || item.address || 'n/a')}</code>`
  ];

  if (data.dexUrl || item.dexUrl) {
    lines.push(`<b>DexScreener:</b> ${escapeTelegramHtml(data.dexUrl || item.dexUrl)}`);
  }

  return lines.join('\n');
}

async function sendTelegramMessage(message) {
  if (!TELEGRAM_ENABLED) return { ok: false, reason: 'telegram_disabled' };

  const url = `https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`;

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      chat_id: TG_CHAT_ID,
      text: message,
      parse_mode: 'HTML',
      disable_web_page_preview: true
    })
  });

  const text = await response.text();
  let payload;

  try {
    payload = JSON.parse(text);
  } catch {
    payload = { raw: text };
  }

  if (!response.ok || payload?.ok === false) {
    throw new Error(payload?.description || text || `Telegram HTTP ${response.status}`);
  }

  return { ok: true, payload };
}

async function processTelegramAlerts(result) {
  if (!TELEGRAM_ENABLED || !result || !result.item) return;

  const importantAlerts = getImportantTelegramAlerts(result);
  if (importantAlerts.length === 0) return;

  for (const alert of importantAlerts) {
    const decision = shouldSendTelegramAlert(result, alert);

    if (!decision.send) continue;

    const message = buildTelegramMessage(result, alert);

    try {
      await sendTelegramMessage(message);
      const sentAtMs = Date.now();
      telegramAlertMemory.set(decision.alertKey, sentAtMs);

      appendVaultRecord(
        VAULT_FILES.telegramAlerts,
        {
          alertKey: decision.alertKey,
          alertLevel: alert.level,
          tokenAddress: result.data?.tokenAddress || result.item.address,
          label: result.item.label,
          source: result.item.source,
          status: result.statusType,
          opportunityScore: result.opportunityScore,
          riskLevel: result.data?.riskLevel || null,
          riskScore: result.data?.riskScore ?? null,
          dexUrl: result.data?.dexUrl || result.item.dexUrl || null,
          message,
          sentAtMs
        },
        { maxRecords: 2000 }
      );

      console.log(`[TELEGRAM] Sent ${alert.level} for ${result.item.label}`);
      await sleep(TELEGRAM_SEND_DELAY_MS);
    } catch (error) {
      console.log(`[TELEGRAM] Failed to send alert ${alert.level} for ${result.item.label}: ${error.message}`);
    }
  }
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
  console.log(`Liquidity:    ${fmtUsd(data.liquidity)}`);
  console.log(`Volume 24h:   ${fmtUsd(data.volume24h)}`);
  console.log(`Txns 24h:     ${data?.txns24h?.total || 0}`);
  console.log(`Buys/Sells:   ${data?.txns24h?.buys || 0}/${data?.txns24h?.sells || 0}`);
  console.log(`DEX:          ${data.dex}`);
  console.log(`Pair:         ${data.pairAddress}`);
  console.log(`Token:        ${data.tokenAddress}`);
  console.log(`Dex URL:      ${data.dexUrl}`);
  console.log(`API Mode:     ${data.scannerApiMode || data.mode || 'unknown'}`);
  console.log(`Cache Hit:    ${data.cacheHit === true ? 'true' : 'false'}`);
  console.log(`Data Age:     ${data.dataAgeSeconds ?? 0}s`);
  console.log(`API Time:     ${data.responseTimeMs ?? 'n/a'}ms`);
  console.log('');
  console.log('ALERTS:');

  for (const alert of alerts) console.log(`- [${alert.level}] ${alert.message}`);

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
  console.log(`Liq:          ${fmtUsd(item.prefilter?.liquidityUsd)}`);
  console.log(`Vol 24h:      ${fmtUsd(item.prefilter?.volume24hUsd)}`);
  console.log(`Txns 24h:     ${item.prefilter?.txns24hTotal || 0}`);
  console.log(`Buys/Sells:   ${item.prefilter?.buys24h || 0}/${item.prefilter?.sells24h || 0}`);
  console.log(`Buy/Sell:     ${numberValue(item.prefilter?.buySellRatio).toFixed(2)}`);
  console.log(`Pre Score:    ${item.prefilter?.prefilterScore || 0}/100`);
  console.log(`Reason:       ${item.prefilter?.rejectReason || 'unknown'}`);
  console.log('==================================================');
}

async function scanToken(item) {
  try {
    const previous = getPreviousSnapshot(item.label);
    const data = await callShieldAPI(item);
    const currentSnapshot = createSnapshotFromData(data);
    const { alerts, opportunityScore } = analyzeFrequency(item.label, currentSnapshot, previous, item.source);

    if (data.status === 'BLOCKED') blockedMemory.add(item.address);

    saveSnapshot(item.label, currentSnapshot);
    printTokenResult(item, data, alerts, opportunityScore);

    const result = { item, data, statusType: data.status, opportunityScore, alerts };
    saveScanResultToVault(result);
    await processTelegramAlerts(result);
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
        alerts: [{ level: 'SKIPPED_NOT_TRADABLE', message: `${item.label} is not tradable/indexed by ShieldAPI yet.` }]
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

    const result = {
      item,
      data: null,
      statusType: 'ERROR',
      opportunityScore: 0,
      alerts: [{ level: 'ERROR', message: error.message }]
    };

    await processTelegramAlerts(result);
    return result;
  }
}

function normalizeDiscoveredPair(pair) {
  const chainId = pair?.chainId;
  const address = pair?.baseToken?.address;

  if (chainId !== 'solana') return null;
  if (!address) return null;

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

  return {
    label: buildCleanDiscoveryLabel(pair, address),
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

  if (chainId !== 'solana') return null;
  if (!address) return null;

  return {
    label: buildCleanDiscoveryLabel(profile, address),
    address,
    source: 'DISCOVERY',
    prefilter: null
  };
}

async function discoverFromTokenProfiles() {
  try {
    const profiles = await getJson('https://api.dexscreener.com/token-profiles/latest/v1');
    if (!Array.isArray(profiles)) return [];
    return profiles.map(normalizeDiscoveredProfile).filter(Boolean);
  } catch (error) {
    console.log(`[DISCOVERY] token-profiles failed: ${error.message}`);
    return [];
  }
}

async function discoverFromBoostsLatest() {
  try {
    const boosts = await getJson('https://api.dexscreener.com/token-boosts/latest/v1');
    if (!Array.isArray(boosts)) return [];
    return boosts.map(normalizeDiscoveredProfile).filter(Boolean);
  } catch (error) {
    console.log(`[DISCOVERY] token-boosts latest failed: ${error.message}`);
    return [];
  }
}

async function discoverFromBoostsTop() {
  try {
    const boosts = await getJson('https://api.dexscreener.com/token-boosts/top/v1');
    if (!Array.isArray(boosts)) return [];
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
    if (!Array.isArray(data?.pairs)) return [];
    return data.pairs.map(normalizeDiscoveredPair).filter(Boolean);
  } catch (error) {
    console.log(`[DISCOVERY] search "${query}" failed: ${error.message}`);
    return [];
  }
}

function shouldRejectByPrefilter(candidate) {
  const metrics = candidate.prefilter;

  if (!metrics) return { rejected: false, reason: null };

  if (metrics.liquidityUsd < DISCOVERY_PREFILTER.minLiquidityUsd) {
    return { rejected: true, reason: `liquidity_below_${DISCOVERY_PREFILTER.minLiquidityUsd}` };
  }

  if (metrics.volume24hUsd < DISCOVERY_PREFILTER.minVolume24hUsd) {
    return { rejected: true, reason: `volume24h_below_${DISCOVERY_PREFILTER.minVolume24hUsd}` };
  }

  if (metrics.txns24hTotal < DISCOVERY_PREFILTER.minTxns24h) {
    return { rejected: true, reason: `txns24h_below_${DISCOVERY_PREFILTER.minTxns24h}` };
  }

  if (metrics.buySellRatio < DISCOVERY_PREFILTER.minBuySellRatio) {
    return { rejected: true, reason: `buy_sell_ratio_below_${DISCOVERY_PREFILTER.minBuySellRatio}` };
  }

  return { rejected: false, reason: null };
}

function dedupeCandidates(candidates) {
  const byAddress = new Map();
  const officialAddresses = new Set(OFFICIAL_WATCHLIST.map((item) => item.address));

  for (const candidate of candidates) {
    if (!candidate?.address) continue;
    if (officialAddresses.has(candidate.address)) continue;
    if (blockedMemory.has(candidate.address)) continue;
    if (skippedMemory.has(candidate.address)) continue;
    if (prefilterRejectedMemory.has(candidate.address)) continue;

    if (!byAddress.has(candidate.address)) {
      byAddress.set(candidate.address, candidate);
      continue;
    }

    const existing = byAddress.get(candidate.address);
    const existingScore = existing?.prefilter?.prefilterScore || 0;
    const candidateScore = candidate?.prefilter?.prefilterScore || 0;

    if (candidateScore > existingScore) byAddress.set(candidate.address, candidate);
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

  return { passed, rejected };
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
      { sortByOpportunity: true, maxRecords: 5000 }
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
    for (const item of rejected.slice(0, 5)) printPrefilterRejected(item);
  }

  return limited;
}

function buildLoopSummary(results) {
  const valid = results.filter(Boolean);

  const official = valid.filter((result) => result.item.source === 'OFFICIAL' || result.item.source === 'TEST_BLOCKED');
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
      riskScore: numberValue(result.data?.riskScore),
      liquidity: numberValue(result.data?.liquidity),
      volume24h: numberValue(result.data?.volume24h),
      dex: result.data?.dex || result.item.dex || null,
      dexUrl: result.data?.dexUrl || result.item.dexUrl || null,
      apiMode: result.data?.scannerApiMode || result.data?.mode || null,
      cacheHit: result.data?.cacheHit === true,
      apiResponseTimeMs: numberValue(result.data?.responseTimeMs)
    }));

  return {
    version: VERSION,
    name: 'ScannerAgent Telegram Alerts',
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
      prefilterRejected: prefilterRejectedMemory.size,
      telegramAlerts: telegramAlertMemory.size
    },
    telegram: {
      enabled: TELEGRAM_ENABLED,
      minOpportunityScore: TELEGRAM_MIN_OPPORTUNITY_SCORE,
      dedupTtlMinutes: Math.round(TELEGRAM_ALERT_DEDUP_TTL_MS / 60000)
    },
    strongestDiscovery
  };
}

function saveLoopSummary(summary) {
  const previous = readJsonFile(VAULT_FILES.scannerSummary, {});
  const loopCount = Number(previous.loopCount || 0) + 1;
  writeJsonFile(VAULT_FILES.scannerSummary, { ...summary, loopCount });
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
  console.log(`Telegram memory:        ${summary.memory.telegramAlerts}`);
  console.log(`Telegram enabled:       ${summary.telegram.enabled}`);
  console.log('--------------------------------------------------');

  if (summary.strongestDiscovery.length === 0) {
    console.log('Top discovery candidates: none');
  } else {
    console.log('Top discovery candidates:');

    for (const result of summary.strongestDiscovery) {
      console.log(
        `- ${result.label} | opp=${result.opportunityScore}/100 | mode=${result.apiMode || 'unknown'} | cache=${result.cacheHit} | api=${result.apiResponseTimeMs}ms | liq=${fmtUsd(result.liquidity)} | vol24h=${fmtUsd(result.volume24h)} | ${result.dexUrl}`
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
  console.log(` ShieldAPI AI Agent / Frequency Scanner v${VERSION}`);
  console.log(' Telegram Alerts Enabled');
  console.log('==============================================');
  console.log(`ShieldAPI URL: ${SHIELD_API_URL}`);
  console.log(`Official watchlist: ${OFFICIAL_WATCHLIST.map((item) => item.label).join(', ')}`);
  console.log(`Interval: ${SCAN_INTERVAL_MS / 1000} seconds`);
  console.log(`Discovery limit: ${DISCOVERY_PREFILTER.maxDiscoveryPerLoop}`);
  console.log(`Discovery min liquidity: ${fmtUsd(DISCOVERY_PREFILTER.minLiquidityUsd)}`);
  console.log(`Discovery min volume 24h: ${fmtUsd(DISCOVERY_PREFILTER.minVolume24hUsd)}`);
  console.log(`Discovery min txns 24h: ${DISCOVERY_PREFILTER.minTxns24h}`);
  console.log(`Analyze fast first: ${USE_ANALYZE_FAST_FIRST}`);
  console.log(`Telegram enabled: ${TELEGRAM_ENABLED}`);
  console.log(`Telegram min score: ${TELEGRAM_MIN_OPPORTUNITY_SCORE}`);
  console.log(`Vault folder: ${DATA_DIR}`);
  console.log('Mode: analyze-fast first + deep fallback + telegram alerts + persistent vault');
  console.log('==============================================');

  if (!TELEGRAM_ENABLED) {
    console.log('[TELEGRAM] Disabled. Set TG_BOT_TOKEN and TG_CHAT_ID to enable alerts.');
  }

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
