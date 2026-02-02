const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { hashToken } = require('../utils/security');

// Middleware to authenticate user
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Oturum açmanız gerekiyor.' });

    const token = authHeader.replace('Bearer ', '');
    const tokenHash = hashToken(token);

    try {
        const result = await pool.query(`
            SELECT s.*, u.username, u.status 
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = $1 AND s.expires_at > NOW()
        `, [tokenHash]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Oturum geçersiz veya süresi dolmuş.' });
        }

        req.user = result.rows[0]; // active session user
        next();
    } catch (e) {
        console.error('Auth Middleware Error:', e);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
};

// GET /me - Get own profile
router.get('/me', authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                u.id, u.username, u.created_at,
                p.display_name, p.avatar_url, p.bio, p.tags
            FROM users u
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE u.id = $1
        `, [req.user.user_id]);

        if (result.rows.length === 0) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

        res.json({ success: true, user: result.rows[0] });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// PUT /me/profile - Update profile
router.put('/me/profile', authenticate, async (req, res) => {
    const { display_name, avatar_url, bio, tags } = req.body;

    // Validations
    if (display_name && display_name.trim().length === 0) {
        return res.status(400).json({ error: 'Görünen isim boş olamaz.' });
    }

    // Default to existing username if display_name is missing?
    // User requested: "görünen isim değiştirilebilecek birde altta değiştirilemez şekilde kullanıcı adı yazıcak"
    // So display_name is key.

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
        res.json({ success: true, profile: result.rows[0] });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

module.exports = router;
