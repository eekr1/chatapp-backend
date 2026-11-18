const express = require('express');
const rateLimit = require('express-rate-limit');
const { pool } = require('../db');
const { authenticate } = require('../utils/sessionService');
const { sendApiError } = require('../utils/i18n');
const { resolvePeerAddress } = require('../utils/abuseProtection');
const matchQuota = require('../utils/matchQuota');
const adRewards = require('../utils/adRewards');

const router = express.Router();

const ssvConfig = adRewards.resolveSsvConfig(process.env);
const ssvKeyLoader = adRewards.createVerifierKeyLoader({
    url: ssvConfig.verifierKeysUrl,
    ttlMs: ssvConfig.keyCacheTtlMs
});

// The SSV callback is unauthenticated by design (Google's servers call it),
// so it gets its own strict limiter on top of the shared /api limiter.
const ssvLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => 'peer:' + resolvePeerAddress(req),
    handler: (req, res) => {
        const retryAfterMs = Math.max(0, Number(req.rateLimit?.resetTime || 0) - Date.now());
        return sendApiError(req, res, 429, 'RATE_LIMITED', {}, 'errors.RATE_LIMIT', {
            retryable: true, retryAfterMs, metadata: { policy: 'admob-ssv' }
        });
    }
});

// GET /api/match-quota -> { quota }
router.get('/match-quota', authenticate, async (req, res) => {
    try {
        const quota = await matchQuota.getQuota(pool, req.user.user_id);
        return res.json({ quota });
    } catch (error) {
        console.error('GET /api/match-quota error:', error?.code || error?.message || error);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// POST /api/ads/reward-session -> { nonce, expiresAt }
router.post('/ads/reward-session', authenticate, async (req, res) => {
    try {
        const quota = await matchQuota.getQuota(pool, req.user.user_id);
        if (!quota.rewardedAvailable) {
            return res.status(409).json({ code: 'AD_LIMIT_REACHED', quota });
        }
        // Opportunistic housekeeping: drop long-expired sessions (small batch);
        // failures must never block issuing a new nonce.
        try {
            await adRewards.purgeExpiredRewardSessions(pool);
        } catch (cleanupError) {
            console.warn('reward-session cleanup skipped:', cleanupError?.message || cleanupError);
        }
        // Invalidate the user's oldest outstanding nonce when too many are live.
        await adRewards.ensureRewardSessionCapacity(pool, req.user.user_id);
        const nonce = adRewards.createNonce();
        const expiresAt = new Date(Date.now() + adRewards.NONCE_TTL_MS);
        await pool.query(
            'INSERT INTO ad_reward_sessions (nonce, user_id, expires_at) VALUES ($1, $2, $3)',
            [nonce, req.user.user_id, expiresAt]
        );
        return res.json({ nonce, expiresAt: expiresAt.toISOString() });
    } catch (error) {
        console.error('POST /api/ads/reward-session error:', error?.code || error?.message || error);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// GET /api/ads/admob-ssv (no auth; called by Google). Definitive verification
// outcomes (bad signature/params, spent or unknown nonce, duplicate
// transaction, disallowed ad unit, daily cap, SSV disabled) answer HTTP 200:
// Google must not retry them, they simply earn nothing. Transient problems —
// verifier keys unavailable or an unexpected server/DB error — answer HTTP 503
// so AdMob retries the callback later.
const ssvHttpStatus = (outcome) => (outcome?.transient === true ? 503 : 200);

router.get('/ads/admob-ssv', ssvLimiter, async (req, res) => {
    const rawQuery = req.originalUrl.includes('?')
        ? req.originalUrl.slice(req.originalUrl.indexOf('?') + 1)
        : '';
    try {
        const outcome = await adRewards.processRewardCallback({
            db: pool,
            rawQuery,
            loadKeys: ssvKeyLoader
        });
        if (!outcome.ok || !outcome.credited) {
            console.warn('admob ssv callback not credited', { reason: outcome.reason || 'unknown', transient: outcome.transient === true });
        }
        const status = ssvHttpStatus(outcome);
        if (status !== 200) {
            return res.status(status).json({
                success: false,
                reason: outcome.reason || 'server_error',
                retryable: true
            });
        }
        return res.status(200).json({
            success: outcome.credited === true,
            ...(outcome.reason ? { reason: outcome.reason } : {})
        });
    } catch (error) {
        console.error('admob ssv callback error:', error?.code || error?.message || error);
        return res.status(503).json({ success: false, reason: 'server_error', retryable: true });
    }
});

module.exports = router;
// Pure outcome -> HTTP status mapping, exposed for tests.
module.exports.ssvHttpStatus = ssvHttpStatus;
