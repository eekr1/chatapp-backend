const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { hashToken, comparePassword, hashPassword } = require('../utils/security');
const { calculateLegalStatus, getRequiredLegalVersions } = require('../utils/legalAcceptance');

const DELETE_CONFIRM_TEXT = 'HESABIMI SIL';

const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
        return forwarded.split(',')[0].trim().slice(0, 120);
    }
    return String(req.ip || req.socket?.remoteAddress || '').trim().slice(0, 120) || null;
};

const sendLegalReacceptRequired = (res, legalStatus) => res.status(428).json({
    error: 'Guncel kullanim sartlari ve gizlilik politikasi kabul edilmelidir.',
    code: 'LEGAL_REACCEPT_REQUIRED',
    required_versions: legalStatus?.required || null,
    accepted_versions: legalStatus?.accepted || null
});

const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Oturum acmaniz gerekiyor.' });

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
            return res.status(401).json({ error: 'Oturum gecersiz veya suresi dolmus.' });
        }

        const sessionUser = result.rows[0];
        if (sessionUser.status !== 'active') {
            return res.status(403).json({ error: 'Hesap aktif degil.' });
        }

        req.user = sessionUser;
        return next();
    } catch (e) {
        console.error('Auth Middleware Error:', e);
        return res.status(500).json({ error: 'Sunucu hatasi.' });
    }
};

const requireLegalAcceptance = async (req, res, next) => {
    try {
        const legalStatus = await calculateLegalStatus(pool, req.user.user_id);
        if (legalStatus.requiresReaccept) {
            return sendLegalReacceptRequired(res, legalStatus);
        }
        req.legalStatus = legalStatus;
        return next();
    } catch (e) {
        console.error('Legal acceptance check error:', e);
        return res.status(500).json({ error: 'Legal kontrolu yapilamadi.' });
    }
};

// GET /me - Get own profile
router.get('/me', authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                u.id, u.username, u.created_at,
                p.display_name, p.avatar_url, p.bio, p.tags
             FROM users u
             LEFT JOIN profiles p ON u.id = p.user_id
             WHERE u.id = $1`,
            [req.user.user_id]
        );

        if (result.rows.length === 0) return res.status(404).json({ error: 'Kullanici bulunamadi.' });

        return res.json({ success: true, user: result.rows[0] });
    } catch (e) {
        console.error('GET /me error:', e);
        return res.status(500).json({ error: 'Sunucu hatasi.' });
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
        return res.status(500).json({ error: 'Legal durum bilgisi alinamadi.' });
    }
});

// POST /me/legal-accept
router.post('/me/legal-accept', authenticate, async (req, res) => {
    const termsVersion = String(req.body?.terms_version || '').trim();
    const privacyVersion = String(req.body?.privacy_version || '').trim();

    if (!termsVersion || !privacyVersion) {
        return res.status(400).json({ error: 'Terms ve privacy versiyonlari zorunludur.' });
    }

    try {
        const required = await getRequiredLegalVersions(pool);
        if (termsVersion !== required.terms || privacyVersion !== required.privacy) {
            return res.status(400).json({
                error: 'Guncel versiyon ile kabul edilmelidir.',
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
        return res.status(500).json({ error: 'Legal kabul kaydedilemedi.' });
    }
});

// PUT /me/profile - Update profile
router.put('/me/profile', authenticate, requireLegalAcceptance, async (req, res) => {
    const { display_name, avatar_url, bio, tags } = req.body || {};

    if (display_name && !String(display_name).trim()) {
        return res.status(400).json({ error: 'Gorunen isim bos olamaz.' });
    }

    try {
        const query = `
            UPDATE profiles
            SET
                display_name = COALESCE($1, display_name),
                avatar_url = COALESCE($2, avatar_url),
                bio = COALESCE($3, bio),
                tags = COALESCE($4, tags),
                updated_at = NOW()
            WHERE user_id = $5
            RETURNING *
        `;
        const values = [
            display_name || null,
            avatar_url || null,
            bio || null,
            tags ? JSON.stringify(tags) : null,
            req.user.user_id
        ];

        const result = await pool.query(query, values);
        return res.json({ success: true, profile: result.rows[0] });
    } catch (e) {
        console.error('PUT /me/profile error:', e);
        return res.status(500).json({ error: 'Sunucu hatasi.' });
    }
});

// PUT /me/password - Change password
router.put('/me/password', authenticate, requireLegalAcceptance, async (req, res) => {
    const currentPassword = String(req.body?.current_password || '');
    const newPassword = String(req.body?.new_password || '');

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Mevcut sifre ve yeni sifre gerekli.' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Yeni sifre en az 6 karakter olmali.' });
    }
    if (currentPassword === newPassword) {
        return res.status(400).json({ error: 'Yeni sifre mevcut sifre ile ayni olamaz.' });
    }

    try {
        const userRes = await pool.query(
            'SELECT password_hash FROM users WHERE id = $1',
            [req.user.user_id]
        );
        if (userRes.rows.length === 0) {
            return res.status(404).json({ error: 'Kullanici bulunamadi.' });
        }

        const isValidCurrent = await comparePassword(currentPassword, userRes.rows[0].password_hash);
        if (!isValidCurrent) {
            return res.status(401).json({ error: 'Mevcut sifre hatali.' });
        }

        const newHash = await hashPassword(newPassword);
        await pool.query(
            'UPDATE users SET password_hash = $1, last_seen_at = NOW() WHERE id = $2',
            [newHash, req.user.user_id]
        );

        return res.json({ success: true, message: 'Sifre guncellendi.' });
    } catch (e) {
        console.error('Password change error:', e);
        return res.status(500).json({ error: 'Sunucu hatasi.' });
    }
});

// POST /me/delete-request - Create account deletion request
router.post('/me/delete-request', authenticate, requireLegalAcceptance, async (req, res) => {
    const currentPassword = String(req.body?.current_password || '');
    const confirmText = String(req.body?.confirm_text || '').trim();

    if (!currentPassword) {
        return res.status(400).json({ error: 'Mevcut sifre gerekli.' });
    }
    if (confirmText !== DELETE_CONFIRM_TEXT) {
        return res.status(400).json({ error: `Onay metni tam olarak "${DELETE_CONFIRM_TEXT}" olmalidir.` });
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
            return res.status(404).json({ error: 'Kullanici bulunamadi.' });
        }

        const dbUser = userRes.rows[0];
        if (dbUser.status !== 'active' && dbUser.status !== 'pending_deletion') {
            await db.query('ROLLBACK');
            return res.status(403).json({ error: 'Hesap durumu bu isleme uygun degil.' });
        }

        const isValidPassword = await comparePassword(currentPassword, dbUser.password_hash);
        if (!isValidPassword) {
            await db.query('ROLLBACK');
            return res.status(401).json({ error: 'Mevcut sifre hatali.' });
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
        return res.json({ success: true, message: 'Silme talebiniz alindi.' });
    } catch (e) {
        try {
            await db.query('ROLLBACK');
        } catch {
            // ignore rollback errors
        }
        console.error('Delete request error:', e);
        return res.status(500).json({ error: 'Sunucu hatasi.' });
    } finally {
        db.release();
    }
});

module.exports = router;
