const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { calculateLegalStatus, legalStatusPayload } = require('../utils/legalAcceptance');
const { normalizeLang, sendApiError } = require('../utils/i18n');
const { authenticate: authenticateSession } = require('../utils/sessionService');

const authenticate = async (req, res, next) => {
    return authenticateSession(req, res, async () => {
        try {
            const legalStatus = await calculateLegalStatus(pool, req.user.user_id);
            if (legalStatus.requiresReaccept) {
                return sendApiError(req, res, 428, 'LEGAL_REACCEPT_REQUIRED', {}, 'errors.LEGAL_REACCEPT_REQUIRED', {
                    metadata: legalStatusPayload(legalStatus)
                });
            }
            return next();
        } catch { return sendApiError(req, res, 503, 'LEGAL_STATUS_UNAVAILABLE', {}, 'errors.LEGAL_STATUS_UNAVAILABLE', { retryable: true }); }
    });
};

router.use(authenticate);

router.post('/register', async (req, res) => {
    const token = typeof req.body?.token === 'string' ? req.body.token.trim() : '';
    const platform = typeof req.body?.platform === 'string' ? req.body.platform.trim().toLowerCase() : 'android';
    const deviceId = typeof req.body?.deviceId === 'string' ? req.body.deviceId.trim() || null : null;
    const submittedLocale = req.body?.locale;
    const locale = submittedLocale === undefined ? normalizeLang(req.user?.locale, 'en') : normalizeLang(submittedLocale, null);

    if (!token || token.length > 4096 || !['android', 'web'].includes(platform) || (deviceId && deviceId.length > 200) || !locale) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    try {
        await pool.query(
            `INSERT INTO push_devices
              (user_id, device_id, platform, push_token, locale, locale_updated_at, is_active, updated_at, last_seen_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), TRUE, NOW(), NOW())
             ON CONFLICT (push_token)
             DO UPDATE SET
               user_id = EXCLUDED.user_id,
               device_id = EXCLUDED.device_id,
               platform = EXCLUDED.platform,
               locale = EXCLUDED.locale,
               locale_updated_at = NOW(),
               is_active = TRUE,
               updated_at = NOW(),
               last_seen_at = NOW()`,
            [req.userId, deviceId, platform, token, locale]
        );

        // Keep only the latest active token per user+device to prevent duplicate push notifications.
        if (deviceId) {
            await pool.query(
                `UPDATE push_devices
                 SET is_active = FALSE, updated_at = NOW()
                 WHERE user_id = $1
                   AND device_id = $2
                   AND push_token <> $3
                   AND is_active = TRUE`,
                [req.userId, deviceId, token]
            );
        }

        res.json({ success: true, locale, locale_source: submittedLocale === undefined ? 'profile' : 'device' });
    } catch (e) {
        console.error('Push register error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

router.post('/unregister', async (req, res) => {
    const token = typeof req.body?.token === 'string' ? req.body.token.trim() : '';
    const deviceId = typeof req.body?.deviceId === 'string' ? req.body.deviceId.trim() : '';

    if ((!token && !deviceId) || token.length > 4096 || deviceId.length > 200) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    try {
        if (token) {
            await pool.query(
                `UPDATE push_devices
                 SET is_active = FALSE, updated_at = NOW()
                 WHERE user_id = $1 AND push_token = $2`,
                [req.userId, token]
            );
        } else {
            await pool.query(
                `UPDATE push_devices
                 SET is_active = FALSE, updated_at = NOW()
                 WHERE user_id = $1 AND device_id = $2`,
                [req.userId, deviceId]
            );
        }
        res.json({ success: true });
    } catch (e) {
        console.error('Push unregister error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

module.exports = router;
