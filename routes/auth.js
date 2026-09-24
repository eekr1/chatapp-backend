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
const { getRequiredLegalState, buildRequirementFingerprint } = require('../utils/legalAcceptance');
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
        privacy_version,
        expected_release_id,
        command_id
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
    const expectedReleaseId = String(expected_release_id || '').trim();
    const commandId = String(command_id || '').trim();
    if (!submittedTermsVersion || submittedTermsVersion.length > 60 || !submittedPrivacyVersion || submittedPrivacyVersion.length > 60
        || !expectedReleaseId || expectedReleaseId.length > 120 || !commandId || commandId.length > 120) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    try {
        const requestedLocale = normalizeLang(req.body?.locale || req.headers['x-talkx-lang'] || lang, 'en');
        const hashedPassword = await hashPassword(String(password));
        const requestIp = getClientIp(req);
        const requestUserAgent = String(req.headers['user-agent'] || '').trim().slice(0, 400) || null;

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const legalState = await getRequiredLegalState(client, { lock: true });
            if (expectedReleaseId !== legalState.releaseId
                || submittedTermsVersion !== legalState.required.terms
                || submittedPrivacyVersion !== legalState.required.privacy) {
                const error = new Error('Legal release changed.');
                error.code = 'LEGAL_VERSION_MISMATCH';
                error.legalState = legalState;
                throw error;
            }

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
                  (user_id, terms_version, privacy_version, accepted_at, ip, user_agent,
                   release_id, release_revision, requirement_fingerprint, command_id, locale)
                 VALUES ($1, $2, $3, NOW(), $4, $5, $6, $7, $8, $9, $10)`,
                [user.id, submittedTermsVersion, submittedPrivacyVersion, requestIp, requestUserAgent,
                    legalState.releaseId, legalState.revision, buildRequirementFingerprint(legalState.required), commandId, requestedLocale]
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
        if (e?.code === 'LEGAL_VERSION_MISMATCH') {
            return res.status(409).json({
                error: t(lang, 'errors.LEGAL_VERSION_MISMATCH', {}, 'Legal version mismatch.'),
                code: 'LEGAL_VERSION_MISMATCH',
                release_id: e.legalState?.releaseId || null,
                revision: e.legalState?.revision || null,
                required_versions: e.legalState?.required || null
            });
        }
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
