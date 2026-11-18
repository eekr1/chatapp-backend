// AdMob rewarded-ad SSV (server-side verification) + reward session helpers.
// Contract shared with the frontend; do not change JSON shapes unilaterally.
//
// Flow: client asks POST /api/ads/reward-session -> nonce (30 min TTL).
// After the rewarded video, Google calls GET /api/ads/admob-ssv with a signed
// query (custom_data = nonce). We verify the ECDSA signature against Google's
// verifier keys, then credit bonus rights idempotently (transaction_id UNIQUE).
// Definitive invalid payloads answer HTTP 200 and earn nothing; transient
// failures (outcomes flagged transient) answer HTTP 503 so AdMob retries.

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const matchQuota = require('./matchQuota');

const VERIFIER_KEYS_URL = 'https://www.gstatic.com/admob/reward/verifier-keys.json';
const DEFAULT_KEY_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const NONCE_TTL_MS = 30 * 60 * 1000;

const toNonNegativeInt = (value, fallback) => {
    if (value === undefined || value === null || String(value).trim() === '') return fallback;
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed < 0) return fallback;
    return Math.round(parsed);
};

const resolveSsvConfig = (env = process.env) => {
    const base = matchQuota.resolveConfig(env);
    return {
        ...base,
        ssvEnabled: base.admobSsvEnabled,
        rewardedAdUnits: String(env.ADMOB_REWARDED_AD_UNITS || '')
            .split(',')
            .map((item) => item.trim())
            .filter(Boolean),
        keyCacheTtlMs: toNonNegativeInt(env.ADMOB_SSV_KEY_CACHE_TTL_MS, DEFAULT_KEY_CACHE_TTL_MS) || DEFAULT_KEY_CACHE_TTL_MS,
        verifierKeysUrl: String(env.ADMOB_SSV_VERIFIER_KEYS_URL || '').trim() || VERIFIER_KEYS_URL
    };
};

// The signature covers the raw query string with the signature parameter
// removed. Segments are kept untouched (no decode/re-encode) so percent
// encoding stays byte-identical to what Google signed.
const extractSignedContent = (rawQuery) => {
    const raw = String(rawQuery || '');
    return raw.split('&')
        .filter((segment) => !segment.startsWith('signature='))
        .join('&');
};

const decodeSignature = (value) => {
    if (typeof value !== 'string' || value.length === 0) return null;
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const buffer = Buffer.from(padded, 'base64');
    return buffer.length > 0 ? buffer : null;
};

// Supports both shapes of the verifier keys payload:
// { keys: [ { key_id, pem }, ... ] } and a bare array of PEM strings.
// Idempotent: already-normalized { keyId, pem } entries pass through.
const normalizeVerifierKeys = (payload) => {
    const entries = Array.isArray(payload) ? payload : (Array.isArray(payload?.keys) ? payload.keys : []);
    return entries.map((entry) => {
        if (typeof entry === 'string') return { keyId: null, pem: entry };
        const rawId = entry?.key_id !== undefined && entry?.key_id !== null ? entry.key_id : entry?.keyId;
        return {
            keyId: rawId === undefined || rawId === null ? null : String(rawId),
            pem: typeof entry?.pem === 'string' ? entry.pem : ''
        };
    }).filter((entry) => entry.pem.includes('BEGIN'));
};

const verifySsvSignature = ({ signedContent, signature, keys, keyId }) => {
    const normalizedKeys = normalizeVerifierKeys(keys);
    if (normalizedKeys.length === 0) return false;
    const signatureBuffer = decodeSignature(signature);
    if (!signatureBuffer) return false;
    let candidates = normalizedKeys;
    if (keyId !== undefined && keyId !== null && String(keyId) !== '') {
        candidates = normalizedKeys.filter((entry) => entry.keyId === String(keyId));
        if (candidates.length === 0) return false;
    }
    const content = Buffer.from(String(signedContent || ''), 'utf8');
    return candidates.some((entry) => {
        try {
            return crypto.verify('sha256', content, entry.pem, signatureBuffer);
        } catch {
            return false;
        }
    });
};

// Cached loader for Google's verifier keys. fetchImpl injectable for tests.
const createVerifierKeyLoader = ({ fetchImpl, url, ttlMs, now } = {}) => {
    const resolveFetch = fetchImpl || globalThis.fetch;
    const resolveUrl = url || VERIFIER_KEYS_URL;
    const resolveTtl = toNonNegativeInt(ttlMs, DEFAULT_KEY_CACHE_TTL_MS) || DEFAULT_KEY_CACHE_TTL_MS;
    let cache = { keys: null, fetchedAt: 0 };
    return async () => {
        const at = typeof now === 'function' ? now() : Date.now();
        if (cache.keys && at - cache.fetchedAt < resolveTtl) return cache.keys;
        if (typeof resolveFetch !== 'function') throw new Error('No fetch implementation available for verifier keys.');
        const response = await resolveFetch(resolveUrl, { headers: { accept: 'application/json' } });
        if (!response.ok) throw new Error('Verifier keys fetch failed with status ' + response.status);
        const payload = await response.json();
        const keys = normalizeVerifierKeys(payload);
        if (keys.length === 0) throw new Error('Verifier keys payload had no usable keys.');
        cache = { keys, fetchedAt: at };
        return keys;
    };
};

const REQUIRED_PARAMS = ['signature', 'transaction_id', 'custom_data', 'user_id'];

const processRewardCallback = async ({ db, rawQuery, loadKeys, now, config } = {}) => {
    const cfg = config || resolveSsvConfig(process.env);
    const at = now ? new Date(now) : new Date();
    if (!cfg.ssvEnabled) return { ok: true, credited: false, reason: 'ssv_disabled' };

    const raw = String(rawQuery || '');
    const params = new URLSearchParams(raw);
    const missing = REQUIRED_PARAMS.filter((name) => !(params.get(name) || '').trim());
    if (missing.length > 0) return { ok: false, credited: false, reason: 'invalid_params' };

    const signature = params.get('signature');
    const transactionId = params.get('transaction_id').trim();
    const nonce = params.get('custom_data').trim();
    const userIdParam = params.get('user_id').trim();
    const keyId = params.get('key_id');
    const adUnit = (params.get('ad_unit') || '').trim();
    const rewardParam = Number(params.get('reward_amount'));
    const rewardAmount = Number.isFinite(rewardParam) && rewardParam > 0 ? Math.round(rewardParam) : cfg.adRewardMatches;

    // AdMob sends the numeric unit id (e.g. 4754991352); accept full ids (ca-app-pub-x/4754991352) in config too.
    const adUnitAllowed = cfg.rewardedAdUnits.some((entry) => entry === adUnit || entry.split('/').pop() === adUnit);
    if (cfg.rewardedAdUnits.length > 0 && !adUnitAllowed) {
        return { ok: false, credited: false, reason: 'ad_unit_not_allowed' };
    }

    let keys;
    try {
        keys = await loadKeys();
    } catch (error) {
        console.error('admob ssv verifier keys unavailable', { message: error?.message || String(error) });
        // Transient: Google should retry the callback once the keys are reachable.
        return { ok: false, credited: false, reason: 'keys_unavailable', transient: true };
    }

    const signedContent = extractSignedContent(raw);
    if (!verifySsvSignature({ signedContent, signature, keys, keyId })) {
        console.warn('admob ssv signature invalid', { transactionId: transactionId.slice(0, 120) });
        return { ok: false, credited: false, reason: 'signature_invalid' };
    }

    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const sessionResult = await client.query(
            'SELECT user_id, expires_at, used_at FROM ad_reward_sessions WHERE nonce = $1 FOR UPDATE',
            [nonce]
        );
        const session = sessionResult.rows[0] || null;
        const sessionValid = session
            && !session.used_at
            && new Date(session.expires_at).getTime() > at.getTime()
            && String(session.user_id) === userIdParam;
        if (!sessionValid) {
            await client.query('ROLLBACK');
            return { ok: false, credited: false, reason: 'nonce_invalid' };
        }

        const ledgerResult = await client.query(
            'INSERT INTO ad_reward_ledger (user_id, transaction_id, ad_unit, reward_amount, nonce) '
            + 'VALUES ($1, $2, $3, $4, $5) '
            + 'ON CONFLICT (transaction_id) DO NOTHING RETURNING id',
            [userIdParam, transactionId, adUnit || null, rewardAmount, nonce]
        );
        if (ledgerResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return { ok: false, credited: false, reason: 'duplicate_transaction' };
        }

        const credit = await matchQuota.creditAdReward(client, userIdParam, { now: at, rewardAmount, dailyMax: cfg.adDailyMax });
        if (!credit.credited) {
            await client.query('ROLLBACK');
            return { ok: true, credited: false, reason: credit.reason };
        }

        await client.query(
            'UPDATE ad_reward_sessions SET used_at = $2 WHERE nonce = $1 AND used_at IS NULL',
            [nonce, at]
        );
        await client.query('COMMIT');
        return { ok: true, credited: true, reason: null, quota: credit.quota, transactionId };
    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch {
            // connection may already be broken; release below regardless
        }
        throw error;
    } finally {
        client.release();
    }
};

const createNonce = () => uuidv4();

// Cap on live (unused, unexpired) reward sessions a single user may hold.
const MAX_ACTIVE_NONCES_PER_USER = 3;
// Opportunistic cleanup thresholds for the reward-session endpoint.
const SESSION_PURGE_OLDER_THAN_DAYS = 7;
const SESSION_PURGE_BATCH_LIMIT = 200;

// Bounds the number of outstanding nonces per user: when the user already has
// maxActive live sessions, invalidate the oldest one(s) (marking them used so
// their callbacks are rejected as nonce_invalid) to make room for a new one.
const ensureRewardSessionCapacity = async (db, userId, { maxActive = MAX_ACTIVE_NONCES_PER_USER, now } = {}) => {
    const at = now ? new Date(now) : new Date();
    const countResult = await db.query(
        'SELECT COUNT(*)::int AS active FROM ad_reward_sessions '
        + 'WHERE user_id = $1 AND used_at IS NULL AND expires_at > $2',
        [userId, at]
    );
    const active = Number(countResult.rows[0]?.active || 0);
    if (active < maxActive) return { active, pruned: 0 };
    const overflow = active - maxActive + 1;
    const update = await db.query(
        'UPDATE ad_reward_sessions SET used_at = $1 WHERE nonce IN ('
        + 'SELECT nonce FROM ad_reward_sessions '
        + 'WHERE user_id = $2 AND used_at IS NULL AND expires_at > $1 '
        + 'ORDER BY created_at ASC, expires_at ASC LIMIT $3)',
        [at, userId, overflow]
    );
    return { active, pruned: update.rowCount || 0 };
};

// Opportunistic housekeeping run on reward-session creation: deletes sessions
// that expired more than olderThanDays ago, in a small bounded batch so the
// table never grows without limit. User-independent, safe to run concurrently.
const purgeExpiredRewardSessions = async (db, { olderThanDays = SESSION_PURGE_OLDER_THAN_DAYS, limit = SESSION_PURGE_BATCH_LIMIT } = {}) => {
    const result = await db.query(
        "DELETE FROM ad_reward_sessions WHERE nonce IN ("
        + 'SELECT nonce FROM ad_reward_sessions '
        + "WHERE expires_at < NOW() - ($1::int * INTERVAL '1 day') "
        + 'LIMIT $2)',
        [olderThanDays, limit]
    );
    return { deleted: result.rowCount || 0 };
};

module.exports = {
    DEFAULT_KEY_CACHE_TTL_MS,
    NONCE_TTL_MS,
    VERIFIER_KEYS_URL,
    MAX_ACTIVE_NONCES_PER_USER,
    SESSION_PURGE_OLDER_THAN_DAYS,
    SESSION_PURGE_BATCH_LIMIT,
    createNonce,
    createVerifierKeyLoader,
    decodeSignature,
    ensureRewardSessionCapacity,
    extractSignedContent,
    normalizeVerifierKeys,
    processRewardCallback,
    purgeExpiredRewardSessions,
    resolveSsvConfig,
    verifySsvSignature
};
