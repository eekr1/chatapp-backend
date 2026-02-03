const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { hashToken } = require('../utils/security');

// Re-use auth middleware logic or import it if I made it reusable.
// I will copy-paste for now to keep files self-contained or I can move it to `middleware/auth.js`.
// Let's create `middleware/auth.js` first to avoid duplication (DRY).
// Actually, I'll just use the same logic inline or move it in next step.
// For speed, I'll create a quick helper here.

const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Oturum gerekli.' });

    const token = authHeader.replace('Bearer ', '');
    const tokenHash = hashToken(token);

    try {
        const result = await pool.query(`
            SELECT s.*, u.username 
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = $1 AND s.expires_at > NOW()
        `, [tokenHash]);

        if (result.rows.length === 0) return res.status(401).json({ error: 'Oturum geçersiz.' });
        req.user = result.rows[0];
        next();
    } catch (e) {
        res.status(500).json({ error: 'Hata.' });
    }
};

router.use(authenticate);

// Send Friend Request
router.post('/request', async (req, res) => {
    const { target_username } = req.body;
    if (!target_username) return res.status(400).json({ error: 'Kullanıcı adı gerekli.' });

    const myId = req.user.user_id;

    try {
        // Find target user
        const targetRes = await pool.query('SELECT id FROM users WHERE username = $1', [target_username.toLowerCase()]);
        const target = targetRes.rows[0];

        if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
        if (target.id === myId) return res.status(400).json({ error: 'Kendine istek atamazsın.' });

        // Check existing request
        // We order IDs to ensure uniqueness if we used a single row per relation, 
        // BUT my schema definition was (user_id, friend_user_id).
        // Let's see how I defined PK: PRIMARY KEY (user_id, friend_user_id).
        // Typically for friendship we check both directions or use canonical order.
        // Milestone plan: "friendships (user_id, friend_user_id, status: pending/accepted)".
        // Meaning user_id is the requester usually.

        // Check if I blocked them or they blocked me
        const blockCheck = await pool.query(`
            SELECT * FROM blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)
        `, [myId, target.id]);
        if (blockCheck.rows.length > 0) return res.status(403).json({ error: 'Bu kullanıcı ile etkileşime geçemezsiniz.' });

        // Check if friendship exists
        const exists = await pool.query(`
            SELECT * FROM friendships WHERE (user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)
        `, [myId, target.id]);

        if (exists.rows.length > 0) {
            const f = exists.rows[0];
            if (f.status === 'accepted') return res.status(400).json({ error: 'Zaten arkadaşsınız.' });
            if (f.status === 'pending') {
                if (f.user_id === myId) return res.status(400).json({ error: 'İstek zaten gönderilmiş.' });
                else return res.status(400).json({ error: 'Bu kullanıcı zaten sana istek atmış. İstekleri kontrol et.' });
            }
        }

        // Create Request
        await pool.query(
            'INSERT INTO friendships (user_id, friend_user_id, status) VALUES ($1, $2, $3)',
            [myId, target.id, 'pending']
        );

        res.json({ success: true, message: 'İstek gönderildi.' });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// List Friends & Requests
router.get('/list', async (req, res) => {
    const myId = req.user.user_id;
    try {
        const result = await pool.query(`
            SELECT 
                f.status,
                u.id as user_id, 
                u.username,
                p.display_name, 
                p.avatar_url,
                -- Verify who sent the request
                CASE WHEN f.user_id = $1 THEN 'outgoing' ELSE 'incoming' END as direction
            FROM friendships f
            JOIN users u ON (f.user_id = u.id OR f.friend_user_id = u.id)
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE (f.user_id = $1 OR f.friend_user_id = $1)
            AND u.id != $1 -- Filter out myself
        `, [myId]);

        const friends = result.rows.filter(r => r.status === 'accepted');
        const requests = result.rows.filter(r => r.status === 'pending'); // Both directions usually shown in different UI tabs

        // Incoming requests: status=pending AND direction=incoming
        const incoming = requests.filter(r => r.direction === 'incoming');
        const outgoing = requests.filter(r => r.direction === 'outgoing');

        res.json({ success: true, friends, incoming, outgoing });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatası.' });
    }
});

// Accept Request
router.post('/accept', async (req, res) => {
    const { request_user_id } = req.body; // The user who sent the request
    const myId = req.user.user_id;

    try {
        const result = await pool.query(`
            UPDATE friendships 
            SET status = 'accepted', updated_at = NOW()
            WHERE user_id = $1 AND friend_user_id = $2 AND status = 'pending'
            RETURNING *
        `, [request_user_id, myId]); // I am friend_user_id (recipient)

        if (result.rows.length === 0) return res.status(404).json({ error: 'İstek bulunamadı.' });

        res.json({ success: true, message: 'Kabul edildi.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Hata.' });
    }
});

// Reject Request (or Delete Friend)
router.post('/reject', async (req, res) => {
    const { target_user_id } = req.body;
    const myId = req.user.user_id;

    try {
        // Delete record regardless of who initiated
        const result = await pool.query(`
            DELETE FROM friendships 
            WHERE ((user_id = $1 AND friend_user_id = $2) OR (user_id = $2 AND friend_user_id = $1))
        `, [myId, target_user_id]);

        res.json({ success: true, message: 'İlişki silindi / Reddedildi.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Hata.' });
    }
});

// GET /history/:friendId - Fetch chat history with a friend
router.get('/history/:friendId', async (req, res) => {
    const myId = req.user.user_id;
    const friendId = req.params.friendId;

    try {
        // 1. Verify Friendship & Get Conversation ID
        const convRes = await pool.query(`
            SELECT id FROM conversations 
            WHERE (user_a_id = $1 AND user_b_id = $2) 
               OR (user_a_id = $2 AND user_b_id = $1)
            ORDER BY started_at DESC LIMIT 1
        `, [myId, friendId]);

        if (convRes.rows.length === 0) return res.json({ success: true, messages: [] });

        const conversationId = convRes.rows[0].id;

        // 2. Fetch Messages
        const msgRes = await pool.query(`
            SELECT sender_id, text, msg_type, created_at 
            FROM messages 
            WHERE conversation_id = $1 
            ORDER BY created_at ASC
        `, [conversationId]);

        // Transform for frontend
        const messages = msgRes.rows.map(m => ({
            from: m.sender_id === myId ? 'me' : 'peer',
            text: m.text,
            msgType: m.msg_type,
            createdAt: m.created_at
        }));

        res.json({ success: true, messages });
    } catch (e) {
        console.error('History API error:', e);
        res.status(500).json({ error: 'Geçmiş yüklenemedi.' });
    }
});

module.exports = router;
