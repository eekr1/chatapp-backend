const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { hashPassword, comparePassword } = require('../utils/security');
const {
    authenticate,
    createSession,
    parseBearerToken,
    revokeAllForUser,
    revokeCurrent
} = require('../utils/sessionService');
const { buildSuccessMeta } = require('../utils/contracts');
const { fetchLegalSettings } = require('../utils/legalContent');
const { normalizeLang, resolveRequestLang, sendApiError, t } = require('../utils/i18n');

const isBoundedString = (value, min, max) => typeof value === 'string'
    && value.length >= min
    && value.length <= max;

const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
        return forwarded.split(',')[0].trim().slice(0, 120);
    }
    return String(req.ip || req.socket?.remoteAddress || '').trim().slice(0, 120) || null;
};

// Register
router.post('/register', async (req, res) => {
    const {
        username,
        password,
        terms_accepted,
        terms_version,
        privacy_version
    } = req.body || {};

    const lang = resolveRequestLang(req);
    if (!isBoundedString(username, 3, 32) || !isBoundedString(password, 1, 128)) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    const cleanUsername = String(username).trim().toLowerCase();
    if (cleanUsername.length < 3) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }
    if (!/^[a-z0-9_]+$/.test(cleanUsername)) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }
    if (password.length < 6) {
        return sendApiError(req, res, 400, 'WEAK_PASSWORD');
    }
    if (terms_accepted !== true) {
        return sendApiError(req, res, 400, 'LEGAL_ACCEPT_REQUIRED');
    }

    const submittedTermsVersion = String(terms_version || '').trim();
    const submittedPrivacyVersion = String(privacy_version || '').trim();
    if (!submittedTermsVersion || submittedTermsVersion.length > 60 || !submittedPrivacyVersion || submittedPrivacyVersion.length > 60) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    try {
        const { item: legalItem } = await fetchLegalSettings(pool);
        const expectedTermsVersion = String(legalItem?.versions?.terms || 'v1');
        const expectedPrivacyVersion = String(legalItem?.versions?.privacy || 'v1');

        if (
            submittedTermsVersion !== expectedTermsVersion
            || submittedPrivacyVersion !== expectedPrivacyVersion
        ) {
            return sendApiError(req, res, 400, 'LEGAL_VERSION_MISMATCH');
        }

        const requestedLocale = normalizeLang(req.body?.locale || req.headers['x-talkx-lang'] || lang, 'en');
        const hashedPassword = await hashPassword(String(password));
        const requestIp = getClientIp(req);
        const requestUserAgent = String(req.headers['user-agent'] || '').trim().slice(0, 400) || null;

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const userRes = await client.query(
                'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
                [cleanUsername, hashedPassword]
            );
            const user = userRes.rows[0];

            await client.query(
                'INSERT INTO profiles (user_id, display_name, locale) VALUES ($1, $2, $3)',
                [user.id, user.username, requestedLocale]
            );

            await client.query(
                `INSERT INTO legal_acceptances
                  (user_id, terms_version, privacy_version, accepted_at, ip, user_agent)
                 VALUES ($1, $2, $3, NOW(), $4, $5)`,
                [user.id, submittedTermsVersion, submittedPrivacyVersion, requestIp, requestUserAgent]
            );

            await client.query('COMMIT');
            return res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    locale: requestedLocale
                }
            });
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    } catch (e) {
        if (e.code === '23505') {
            return res.status(409).json({
                error: lang === 'tr' ? 'Bu kullanici adi zaten alinmis.' : 'This username is already taken.',
                code: 'USERNAME_TAKEN'
            });
        }
        console.error('Register Error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// Login
router.post('/login', async (req, res) => {
    const lang = resolveRequestLang(req);
    const { username, password, device_id } = req.body || {};
    if (!isBoundedString(username, 3, 32) || !isBoundedString(password, 1, 128)) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }
    if (device_id !== undefined && !isBoundedString(device_id, 1, 200)) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    const cleanUsername = String(username).trim().toLowerCase();

    try {
        const userRes = await pool.query(
            `SELECT u.*, p.locale
             FROM users u
             LEFT JOIN profiles p ON p.user_id = u.id
             WHERE u.username = $1`,
            [cleanUsername]
        );
        const user = userRes.rows[0];

        if (!user) return sendApiError(req, res, 401, 'BAD_CREDENTIALS');

        if (user.status !== 'active') {
            return sendApiError(req, res, 403, 'ACCOUNT_INACTIVE');
        }

        const match = await comparePassword(String(password), user.password_hash);
        if (!match) return sendApiError(req, res, 401, 'BAD_CREDENTIALS');

        const requestedLocale = normalizeLang(req.body?.locale || req.headers['x-talkx-lang'] || user.locale || lang, 'en');
        await pool.query('UPDATE profiles SET locale = $1, updated_at = NOW() WHERE user_id = $2', [requestedLocale, user.id]);

        const session = await createSession({ userId: user.id, deviceId: device_id });

        await pool.query('UPDATE users SET last_seen_at = NOW() WHERE id = $1', [user.id]);

        return res.json({
            success: true,
            token: session.token,
            expiresAt: session.expiresAt.toISOString(),
            user: { id: user.id, username: user.username, locale: requestedLocale },
            meta: buildSuccessMeta(req.requestId)
        });
    } catch (e) {
        console.error('Login Error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// Logout
router.post('/logout', async (req, res) => {
    const token = parseBearerToken(req.headers.authorization);
    if (!token) return res.json({ success: true, meta: buildSuccessMeta(req.requestId) });

    try {
        await revokeCurrent(token, 'logout');
        return res.json({ success: true, scope: 'current', meta: buildSuccessMeta(req.requestId) });
    } catch (e) {
        console.error('Logout Error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

router.post('/logout-all', authenticate, async (req, res) => {
    try {
        await revokeAllForUser(req.user.user_id, 'logout_all');
        return res.json({ success: true, scope: 'all', meta: buildSuccessMeta(req.requestId) });
    } catch (e) {
        console.error('Logout all error:', e?.message || e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

module.exports = router;
