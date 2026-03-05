const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { hashPassword, comparePassword, generateSessionToken, hashToken } = require('../utils/security');
const { fetchLegalSettings } = require('../utils/legalContent');

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

    if (!username || !password) {
        return res.status(400).json({ error: 'Kullanici adi ve sifre gerekli.' });
    }

    const cleanUsername = String(username).trim().toLowerCase();
    if (cleanUsername.length < 3) {
        return res.status(400).json({ error: 'Kullanici adi en az 3 karakter olmali.' });
    }
    if (String(password).length < 6) {
        return res.status(400).json({ error: 'Sifre en az 6 karakter olmali.' });
    }
    if (!/^[a-z0-9_]+$/.test(cleanUsername)) {
        return res.status(400).json({ error: 'Kullanici adi sadece harf, rakam ve alt cizgi icerebilir.' });
    }
    if (terms_accepted !== true) {
        return res.status(400).json({ error: 'Kayit icin kullanim sartlari ve gizlilik politikasi kabul edilmelidir.' });
    }

    const submittedTermsVersion = String(terms_version || '').trim();
    const submittedPrivacyVersion = String(privacy_version || '').trim();
    if (!submittedTermsVersion || !submittedPrivacyVersion) {
        return res.status(400).json({ error: 'Sozlesme versiyon bilgisi eksik.' });
    }

    try {
        const { item: legalItem } = await fetchLegalSettings(pool);
        const expectedTermsVersion = String(legalItem?.versions?.terms || 'v1');
        const expectedPrivacyVersion = String(legalItem?.versions?.privacy || 'v1');

        if (
            submittedTermsVersion !== expectedTermsVersion
            || submittedPrivacyVersion !== expectedPrivacyVersion
        ) {
            return res.status(400).json({ error: 'Sozlesme versiyonu guncel degil. Lutfen sayfayi yenileyip tekrar deneyin.' });
        }

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
                'INSERT INTO profiles (user_id, display_name) VALUES ($1, $2)',
                [user.id, user.username]
            );

            await client.query(
                `INSERT INTO legal_acceptances
                  (user_id, terms_version, privacy_version, accepted_at, ip, user_agent)
                 VALUES ($1, $2, $3, NOW(), $4, $5)`,
                [user.id, submittedTermsVersion, submittedPrivacyVersion, requestIp, requestUserAgent]
            );

            await client.query('COMMIT');
            return res.json({ success: true, user: { id: user.id, username: user.username } });
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    } catch (e) {
        if (e.code === '23505') {
            return res.status(409).json({ error: 'Bu kullanici adi zaten alinmis.' });
        }
        console.error('Register Error:', e);
        return res.status(500).json({ error: 'Sunucu hatasi.' });
    }
});

// Login
router.post('/login', async (req, res) => {
    const { username, password, device_id } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Eksik bilgi.' });

    const cleanUsername = String(username).trim().toLowerCase();

    try {
        const userRes = await pool.query('SELECT * FROM users WHERE username = $1', [cleanUsername]);
        const user = userRes.rows[0];

        if (!user) return res.status(401).json({ error: 'Kullanici adi veya sifre hatali.' });

        if (user.status !== 'active') {
            return res.status(403).json({ error: 'Hesabiniz aktif degil.' });
        }

        const match = await comparePassword(String(password), user.password_hash);
        if (!match) return res.status(401).json({ error: 'Kullanici adi veya sifre hatali.' });

        const token = generateSessionToken();
        const tokenHash = hashToken(token);
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        await pool.query(
            'INSERT INTO sessions (token_hash, user_id, device_id, expires_at) VALUES ($1, $2, $3, $4)',
            [tokenHash, user.id, device_id || 'unknown', expiresAt]
        );

        await pool.query('UPDATE users SET last_seen_at = NOW() WHERE id = $1', [user.id]);

        return res.json({
            success: true,
            token,
            user: { id: user.id, username: user.username }
        });
    } catch (e) {
        console.error('Login Error:', e);
        return res.status(500).json({ error: 'Sunucu hatasi.' });
    }
});

// Logout
router.post('/logout', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.json({ success: true });

    const token = authHeader.replace('Bearer ', '');
    const tokenHash = hashToken(token);

    try {
        await pool.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
        return res.json({ success: true });
    } catch (e) {
        console.error('Logout Error:', e);
        return res.status(500).json({ error: 'Sunucu hatasi.' });
    }
});

module.exports = router;
