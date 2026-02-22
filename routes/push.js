const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { hashToken } = require('../utils/security');

const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Oturum gerekli.' });

    const token = authHeader.replace('Bearer ', '');
    const tokenHash = hashToken(token);

    try {
        const result = await pool.query(
            `SELECT s.user_id
             FROM sessions s
             WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
            [tokenHash]
        );

        if (result.rows.length === 0) return res.status(401).json({ error: 'Oturum gecersiz.' });
        req.userId = result.rows[0].user_id;
        next();
    } catch (e) {
        console.error('Push auth error:', e);
        res.status(500).json({ error: 'Sunucu hatasi.' });
    }
};

router.use(authenticate);

router.post('/register', async (req, res) => {
    const token = (req.body.token || '').trim();
    const platform = (req.body.platform || 'android').trim().toLowerCase();
    const deviceId = (req.body.deviceId || '').trim() || null;

    if (!token) return res.status(400).json({ error: 'Push token gerekli.' });

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
        res.status(500).json({ error: 'Push kaydi basarisiz.' });
    }
});

router.post('/unregister', async (req, res) => {
    const token = (req.body.token || '').trim();
    const deviceId = (req.body.deviceId || '').trim();

    if (!token && !deviceId) {
        return res.status(400).json({ error: 'token veya deviceId gerekli.' });
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
        res.status(500).json({ error: 'Push kaydi kaldirilamadi.' });
    }
});

module.exports = router;
