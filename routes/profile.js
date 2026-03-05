const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { hashToken, comparePassword, hashPassword } = require('../utils/security');
const { calculateLegalStatus, getRequiredLegalVersions } = require('../utils/legalAcceptance');
const { normalizeLang, resolveRequestLang, sendApiError, t } = require('../utils/i18n');

const DELETE_CONFIRM_TEXT = 'HESABIMI SIL';

const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
        return forwarded.split(',')[0].trim().slice(0, 120);
    }
    return String(req.ip || req.socket?.remoteAddress || '').trim().slice(0, 120) || null;
};

const sendLegalReacceptRequired = (req, res, legalStatus) => res.status(428).json({
    error: t(resolveRequestLang(req), 'errors.LEGAL_REACCEPT_REQUIRED', {}, 'Legal reaccept required.'),
    code: 'LEGAL_REACCEPT_REQUIRED',
    required_versions: legalStatus?.required || null,
    accepted_versions: legalStatus?.accepted || null
});

const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return sendApiError(req, res, 401, 'AUTH_REQUIRED');

    const token = authHeader.replace('Bearer ', '');
    const tokenHash = hashToken(token);

    try {
        const result = await pool.query(
            `SELECT s.*, u.username, u.status
             FROM sessions s
             JOIN users u ON s.user_id = u.id
             WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
            [tokenHash]
        );

        if (result.rows.length === 0) {
            return sendApiError(req, res, 401, 'AUTH_INVALID');
        }

        const sessionUser = result.rows[0];
        if (sessionUser.status !== 'active') {
            return sendApiError(req, res, 403, 'ACCOUNT_INACTIVE');
        }

        req.user = sessionUser;
        return next();
    } catch (e) {
        console.error('Auth Middleware Error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
};

const requireLegalAcceptance = async (req, res, next) => {
    try {
        const legalStatus = await calculateLegalStatus(pool, req.user.user_id);
        if (legalStatus.requiresReaccept) {
            return sendLegalReacceptRequired(req, res, legalStatus);
        }
        req.legalStatus = legalStatus;
        return next();
    } catch (e) {
        console.error('Legal acceptance check error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
};

// GET /me - Get own profile
router.get('/me', authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                u.id, u.username, u.created_at,
                p.display_name, p.avatar_url, p.bio, p.tags, p.locale
             FROM users u
             LEFT JOIN profiles p ON u.id = p.user_id
             WHERE u.id = $1`,
            [req.user.user_id]
        );

        if (result.rows.length === 0) return sendApiError(req, res, 404, 'USER_NOT_FOUND');

        return res.json({ success: true, user: result.rows[0] });
    } catch (e) {
        console.error('GET /me error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// GET /me/legal-status
router.get('/me/legal-status', authenticate, async (req, res) => {
    try {
        const status = await calculateLegalStatus(pool, req.user.user_id);
        return res.json({
            success: true,
            required_versions: status.required,
            accepted_versions: status.accepted,
            requires_reaccept: status.requiresReaccept
        });
    } catch (e) {
        console.error('GET /me/legal-status error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// POST /me/legal-accept
router.post('/me/legal-accept', authenticate, async (req, res) => {
    const termsVersion = String(req.body?.terms_version || '').trim();
    const privacyVersion = String(req.body?.privacy_version || '').trim();

    if (!termsVersion || !privacyVersion) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    try {
        const required = await getRequiredLegalVersions(pool);
        if (termsVersion !== required.terms || privacyVersion !== required.privacy) {
            return res.status(400).json({
                error: t(resolveRequestLang(req), 'errors.LEGAL_VERSION_MISMATCH', {}, 'Legal version mismatch.'),
                code: 'LEGAL_VERSION_MISMATCH',
                required_versions: required
            });
        }

        await pool.query(
            `INSERT INTO legal_acceptances
              (user_id, terms_version, privacy_version, accepted_at, ip, user_agent)
             VALUES ($1, $2, $3, NOW(), $4, $5)`,
            [
                req.user.user_id,
                required.terms,
                required.privacy,
                getClientIp(req),
                String(req.headers['user-agent'] || '').trim().slice(0, 400) || null
            ]
        );

        return res.json({
            success: true,
            required_versions: required,
            accepted_versions: {
                terms: required.terms,
                privacy: required.privacy,
                accepted_at: new Date().toISOString()
            }
        });
    } catch (e) {
        console.error('POST /me/legal-accept error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// PUT /me/profile - Update profile
router.put('/me/profile', authenticate, requireLegalAcceptance, async (req, res) => {
    const { display_name, avatar_url, bio, tags, locale } = req.body || {};
    const normalizedLocale = locale === undefined ? undefined : normalizeLang(locale, null);

    if (display_name && !String(display_name).trim()) {
        return sendApiError(req, res, 400, 'PROFILE_NAME_REQUIRED');
    }
    if (locale !== undefined && !normalizedLocale) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    try {
        const query = `
            UPDATE profiles
            SET
                display_name = COALESCE($1, display_name),
                avatar_url = COALESCE($2, avatar_url),
                bio = COALESCE($3, bio),
                tags = COALESCE($4, tags),
                locale = COALESCE($5, locale),
                updated_at = NOW()
            WHERE user_id = $6
            RETURNING *
        `;
        const values = [
            display_name || null,
            avatar_url || null,
            bio || null,
            tags ? JSON.stringify(tags) : null,
            normalizedLocale || null,
            req.user.user_id
        ];

        const result = await pool.query(query, values);
        return res.json({ success: true, profile: result.rows[0] });
    } catch (e) {
        console.error('PUT /me/profile error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// PUT /me/password - Change password
router.put('/me/password', authenticate, requireLegalAcceptance, async (req, res) => {
    const currentPassword = String(req.body?.current_password || '');
    const newPassword = String(req.body?.new_password || '');

    if (!currentPassword || !newPassword) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }
    if (newPassword.length < 6) {
        return sendApiError(req, res, 400, 'WEAK_PASSWORD');
    }
    if (currentPassword === newPassword) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    try {
        const userRes = await pool.query(
            'SELECT password_hash FROM users WHERE id = $1',
            [req.user.user_id]
        );
        if (userRes.rows.length === 0) {
            return sendApiError(req, res, 404, 'USER_NOT_FOUND');
        }

        const isValidCurrent = await comparePassword(currentPassword, userRes.rows[0].password_hash);
        if (!isValidCurrent) {
            return sendApiError(req, res, 401, 'BAD_CREDENTIALS');
        }

        const newHash = await hashPassword(newPassword);
        await pool.query(
            'UPDATE users SET password_hash = $1, last_seen_at = NOW() WHERE id = $2',
            [newHash, req.user.user_id]
        );

        return res.json({
            success: true,
            message: t(resolveRequestLang(req), 'profile.PASSWORD_UPDATED', {}, 'Password updated.')
        });
    } catch (e) {
        console.error('Password change error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// POST /me/delete-request - Create account deletion request
router.post('/me/delete-request', authenticate, requireLegalAcceptance, async (req, res) => {
    const currentPassword = String(req.body?.current_password || '');
    const confirmText = String(req.body?.confirm_text || '').trim();

    if (!currentPassword) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }
    if (confirmText !== DELETE_CONFIRM_TEXT) {
        return sendApiError(req, res, 400, 'DELETE_CONFIRM_REQUIRED');
    }

    const db = await pool.connect();
    try {
        await db.query('BEGIN');

        const userRes = await db.query(
            `SELECT id, username, password_hash, status
             FROM users
             WHERE id = $1
             FOR UPDATE`,
            [req.user.user_id]
        );

        if (!userRes.rows.length) {
            await db.query('ROLLBACK');
            return sendApiError(req, res, 404, 'USER_NOT_FOUND');
        }

        const dbUser = userRes.rows[0];
        if (dbUser.status !== 'active' && dbUser.status !== 'pending_deletion') {
            await db.query('ROLLBACK');
            return sendApiError(req, res, 403, 'ACCOUNT_INACTIVE');
        }

        const isValidPassword = await comparePassword(currentPassword, dbUser.password_hash);
        if (!isValidPassword) {
            await db.query('ROLLBACK');
            return sendApiError(req, res, 401, 'BAD_CREDENTIALS');
        }

        const existingRequested = await db.query(
            `SELECT id
             FROM account_deletion_requests
             WHERE user_id = $1 AND status = 'requested'
             LIMIT 1`,
            [dbUser.id]
        );

        if (!existingRequested.rows.length) {
            await db.query(
                `INSERT INTO account_deletion_requests
                  (user_id, username_snapshot, status, requested_at)
                 VALUES ($1, $2, 'requested', NOW())`,
                [dbUser.id, dbUser.username]
            );
        }

        await db.query(
            `UPDATE users
             SET status = 'pending_deletion', last_seen_at = NOW()
             WHERE id = $1`,
            [dbUser.id]
        );
        await db.query('DELETE FROM sessions WHERE user_id = $1', [dbUser.id]);

        await db.query('COMMIT');
        return res.json({
            success: true,
            message: t(resolveRequestLang(req), 'profile.DELETE_REQUEST_RECEIVED', {}, 'Deletion request received.')
        });
    } catch (e) {
        try {
            await db.query('ROLLBACK');
        } catch {
            // ignore rollback errors
        }
        console.error('Delete request error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    } finally {
        db.release();
    }
});

module.exports = router;
