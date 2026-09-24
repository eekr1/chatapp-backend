const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { comparePassword, hashPassword } = require('../utils/security');
const { authenticate, revokeAllForUser } = require('../utils/sessionService');
const { calculateLegalStatus, acceptLegalRequirement, legalStatusPayload } = require('../utils/legalAcceptance');
const { normalizeLang, resolveRequestLang, sendApiError, t } = require('../utils/i18n');
const { displayCountry } = require('../utils/countryPolicy');
const { requestUserRuntimeTermination } = require('../utils/userRuntimeTermination');

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
    ...legalStatusPayload(legalStatus)
});

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
        return sendApiError(req, res, 503, 'LEGAL_STATUS_UNAVAILABLE', {}, 'errors.LEGAL_STATUS_UNAVAILABLE', { retryable: true });
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
        return res.json({ success: true, ...legalStatusPayload(status) });
    } catch (e) {
        console.error('GET /me/legal-status error:', e);
        return sendApiError(req, res, 503, 'LEGAL_STATUS_UNAVAILABLE', {}, 'errors.LEGAL_STATUS_UNAVAILABLE', { retryable: true });
    }
});

// GET /me/match-country - Server-owned country record. This is not a country selector.
router.get('/me/match-country', authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT country_code, status, confidence, updated_at, policy_version
             FROM user_match_country WHERE user_id = $1`,
            [req.user.user_id]
        );
        const row = result.rows[0] || null;
        const eligible = row?.status === 'eligible';
        const code = eligible ? row.country_code : null;
        return res.json({
            success: true,
            capability: 'country-data-v1',
            country: code ? { code, display_name: displayCountry(code, req.user.locale) } : null,
            status: row?.status || 'unavailable',
            confidence: row?.confidence || 'unknown',
            updated_at: row?.updated_at || null,
            policy_version: row?.policy_version || 'match-country-v1'
        });
    } catch (e) {
        console.error('GET /me/match-country error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// POST /me/legal-accept
router.post('/me/legal-accept', authenticate, async (req, res) => {
    const termsVersion = String(req.body?.terms_version || '').trim();
    const privacyVersion = String(req.body?.privacy_version || '').trim();
    const expectedReleaseId = String(req.body?.expected_release_id || '').trim();
    const commandId = String(req.body?.command_id || '').trim();
    const locale = normalizeLang(req.body?.locale || req.headers['x-talkx-lang'], 'en');

    if (!termsVersion || !privacyVersion || !expectedReleaseId || !commandId
        || expectedReleaseId.length > 120 || commandId.length > 120) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    try {
        const result = await acceptLegalRequirement({
            pool,
            userId: req.user.user_id,
            expectedReleaseId,
            termsVersion,
            privacyVersion,
            commandId,
            locale,
            ip: getClientIp(req),
            userAgent: String(req.headers['user-agent'] || '').trim().slice(0, 400) || null
        });

        return res.json({
            success: true,
            release_id: result.releaseId,
            revision: result.revision,
            required_versions: result.required,
            accepted_versions: result.accepted,
            replayed: result.replayed,
            command_id: commandId
        });
    } catch (e) {
        if (e?.code === 'LEGAL_VERSION_MISMATCH') {
            return res.status(409).json({
                error: t(resolveRequestLang(req), 'errors.LEGAL_VERSION_MISMATCH', {}, 'Legal version mismatch.'),
                code: 'LEGAL_VERSION_MISMATCH',
                release_id: e.legalState?.releaseId || null,
                revision: e.legalState?.revision || null,
                required_versions: e.legalState?.required || null,
                retryable: false
            });
        }
        if (e?.code === 'IDEMPOTENCY_CONFLICT') {
            return sendApiError(req, res, 409, 'IDEMPOTENCY_CONFLICT');
        }
        console.error('POST /me/legal-accept error:', e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// PUT /me/profile - Update profile
router.put('/me/profile', authenticate, requireLegalAcceptance, async (req, res) => {
    const { display_name, avatar_url, bio, tags, locale } = req.body || {};
    const normalizedLocale = locale === undefined ? undefined : normalizeLang(locale, null);

    if (display_name !== undefined && (typeof display_name !== 'string' || !display_name.trim() || display_name.length > 80)) {
        return sendApiError(req, res, 400, 'PROFILE_NAME_REQUIRED');
    }
    if (avatar_url !== undefined && (typeof avatar_url !== 'string' || avatar_url.length > 2048)) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }
    if (bio !== undefined && (typeof bio !== 'string' || bio.length > 500)) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }
    if (tags !== undefined && (!Array.isArray(tags) || tags.length > 20 || tags.some((tag) => typeof tag !== 'string' || tag.length > 40))) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
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

    if (!currentPassword || !newPassword || currentPassword.length > 128 || newPassword.length > 128) {
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
        await revokeAllForUser(req.user.user_id, 'password_changed');

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

    if (!currentPassword || currentPassword.length > 128) {
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

        const idempotencyKey = String(req.get('Idempotency-Key') || '').trim().slice(0, 120) || null;
        const existingRequested = await db.query(
            `SELECT id, status, requested_at, policy_version
             FROM account_deletion_requests
             WHERE user_id = $1
               AND status IN ('requested', 'reviewing', 'approved', 'processing', 'failed_retryable')
             LIMIT 1`,
            [dbUser.id]
        );

        let deletionRequest = existingRequested.rows[0] || null;
        const duplicate = Boolean(deletionRequest);
        if (!existingRequested.rows.length) {
            const inserted = await db.query(
                `INSERT INTO account_deletion_requests
                  (user_id, username_snapshot, status, requested_at, idempotency_key, policy_version)
                 VALUES ($1, $2, 'requested', NOW(), $3, 'talkx-data-policy-v1')
                 RETURNING id, status, requested_at, policy_version`,
                [dbUser.id, dbUser.username, idempotencyKey]
            );
            deletionRequest = inserted.rows[0];
        }

        await db.query(
            `UPDATE users
             SET status = 'pending_deletion', last_seen_at = NOW()
             WHERE id = $1`,
            [dbUser.id]
        );
        await revokeAllForUser(dbUser.id, 'account_deletion_requested', db);

        await db.query('COMMIT');
        let runtimeAck = { listenerCount: 0, acknowledged: 0, failed: 1, retryRequired: true };
        try {
            runtimeAck = await requestUserRuntimeTermination({
                userId: dbUser.id,
                requestId: deletionRequest.id,
                reason: 'account_deletion_requested'
            });
            await pool.query(
                'UPDATE account_deletion_requests SET runtime_ack = $2::jsonb WHERE id = $1',
                [deletionRequest.id, JSON.stringify(runtimeAck)]
            );
        } catch (runtimeError) {
            console.warn('Deletion runtime termination requires retry.', { requestId: deletionRequest.id, code: runtimeError?.code || 'RUNTIME_ACK_FAILED' });
        }
        return res.json({
            success: true,
            request_id: deletionRequest.id,
            status: deletionRequest.status,
            requested_at: deletionRequest.requested_at,
            policy_version: deletionRequest.policy_version,
            runtime_ack: runtimeAck,
            duplicate,
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
