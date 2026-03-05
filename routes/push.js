const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { hashToken } = require('../utils/security');
const { calculateLegalStatus } = require('../utils/legalAcceptance');
const { sendApiError, t, resolveRequestLang } = require('../utils/i18n');

const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return sendApiError(req, res, 401, 'AUTH_REQUIRED');

    const token = authHeader.replace('Bearer ', '');
    const tokenHash = hashToken(token);

    try {
        const result = await pool.query(
            `SELECT s.user_id, u.status
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
            [tokenHash]
        );

        if (result.rows.length === 0) return sendApiError(req, res, 401, 'AUTH_INVALID');
        if (result.rows[0].status !== 'active') {
            return sendApiError(req, res, 403, 'ACCOUNT_INACTIVE');
        }
        const sessionUser = result.rows[0];
        const legalStatus = await calculateLegalStatus(pool, sessionUser.user_id);
        if (legalStatus.requiresReaccept) {
            return res.status(428).json({
                error: t(resolveRequestLang(req), 'errors.LEGAL_REACCEPT_REQUIRED', {}, 'Legal reaccept required.'),
                code: 'LEGAL_REACCEPT_REQUIRED',
                required_versions: legalStatus.required,
                accepted_versions: legalStatus.accepted
            });
        }
        req.userId = sessionUser.user_id;
        next();
    } catch (e) {
        console.error('Push auth error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
};

router.use(authenticate);

router.post('/register', async (req, res) => {
    const token = (req.body.token || '').trim();
    const platform = (req.body.platform || 'android').trim().toLowerCase();
    const deviceId = (req.body.deviceId || '').trim() || null;

    if (!token) return sendApiError(req, res, 400, 'INVALID_INPUT');

    try {
        await pool.query(
            `INSERT INTO push_devices (user_id, device_id, platform, push_token, is_active, updated_at, last_seen_at)
             VALUES ($1, $2, $3, $4, TRUE, NOW(), NOW())
             ON CONFLICT (push_token)
             DO UPDATE SET
               user_id = EXCLUDED.user_id,
               device_id = EXCLUDED.device_id,
               platform = EXCLUDED.platform,
               is_active = TRUE,
               updated_at = NOW(),
               last_seen_at = NOW()`,
            [req.userId, deviceId, platform, token]
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

        res.json({ success: true });
    } catch (e) {
        console.error('Push register error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

router.post('/unregister', async (req, res) => {
    const token = (req.body.token || '').trim();
    const deviceId = (req.body.deviceId || '').trim();

    if (!token && !deviceId) {
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
