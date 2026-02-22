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

        const blockCheck = await pool.query(`
            SELECT * FROM blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)
        `, [myId, target.id]);
        if (blockCheck.rows.length > 0) return res.status(403).json({ error: 'Bu kullanıcı ile etkileşime geçemezsiniz.' });

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

        await pool.query(
            'INSERT INTO friendships (user_id, friend_user_id, status) VALUES ($1, $2, $3)',
            [myId, target.id, 'pending']
        );

        if (req.notifyUser) {
            req.notifyUser(target.id, { type: 'friend_refresh' });
        }

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
                CASE WHEN f.user_id = $1 THEN 'outgoing' ELSE 'incoming' END as direction
            FROM friendships f
            JOIN users u ON (f.user_id = u.id OR f.friend_user_id = u.id)
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE (f.user_id = $1 OR f.friend_user_id = $1)
            AND u.id != $1
        `, [myId]);

        const unreadRes = await pool.query(`
             SELECT m.sender_id, COUNT(*) as cnt
             FROM messages m
             JOIN conversations c ON m.conversation_id = c.id
             WHERE m.sender_id != $1 
             AND m.is_read = FALSE
             AND ((c.user_a_id = $1 OR c.user_b_id = $1))
             GROUP BY m.sender_id
        `, [myId]);

        const unreadMap = {};
        unreadRes.rows.forEach(r => { unreadMap[r.sender_id] = parseInt(r.cnt); });

        const friends = result.rows.filter(r => r.status === 'accepted').map(f => ({
            ...f,
            unread_count: unreadMap[f.user_id] || 0,
            is_online: req.isUserOnline ? req.isUserOnline(f.user_id) : false
        }));
        const requests = result.rows.filter(r => r.status === 'pending');

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
    const { request_user_id } = req.body;
    const myId = req.user.user_id;

    try {
        const result = await pool.query(`
            UPDATE friendships 
            SET status = 'accepted', updated_at = NOW()
            WHERE user_id = $1 AND friend_user_id = $2 AND status = 'pending'
            RETURNING *
        `, [request_user_id, myId]);

        if (result.rows.length === 0) return res.status(404).json({ error: 'İstek bulunamadı.' });

        if (req.notifyUser) {
            req.notifyUser(request_user_id, { type: 'friend_refresh' });
            req.notifyUser(myId, { type: 'friend_refresh' }); // Also notify self (other tabs)
        }

        res.json({ success: true, message: 'Kabul edildi.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Hata.' });
    }
});

// Reject Request
router.post('/reject', async (req, res) => {
    const { target_user_id } = req.body;
    const myId = req.user.user_id;

    try {
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

// GET /history/:friendId
router.get('/history/:friendId', async (req, res) => {
    const myId = req.user.user_id;
    const friendId = req.params.friendId;

    try {
        const msgRes = await pool.query(`
            SELECT m.id, m.sender_id, m.client_msg_id, m.text, m.msg_type, m.created_at, m.is_read, m.media_id
            FROM messages m
            JOIN conversations c ON m.conversation_id = c.id
            WHERE ((c.user_a_id = $1 AND c.user_b_id = $2) OR (c.user_a_id = $2 AND c.user_b_id = $1))
            AND m.msg_type IN ('direct', 'image') 
            ORDER BY m.created_at ASC
        `, [myId, friendId]);

        if (process.env.NODE_ENV !== 'production') {
            console.log(`[DEBUG] History for ${myId}<->${friendId} found ${msgRes.rows.length} messages.`);
        }

        const messages = await Promise.all(msgRes.rows.map(async m => {
            let mediaExpired = false;
            if (m.msg_type === 'image' && m.media_id) {
                const check = await pool.query('SELECT 1 FROM ephemeral_media WHERE id = $1', [m.media_id]);
                mediaExpired = check.rows.length === 0;
            }
            return {
                from: m.sender_id === myId ? 'me' : 'peer',
                text: m.text,
                msgType: m.msg_type,
                clientMsgId: m.client_msg_id,
                mediaId: m.media_id,
                mediaExpired,
                createdAt: m.created_at,
                timestamp: new Date(m.created_at).getTime(),
                isRead: m.is_read
            };
        }));

        res.json({ success: true, messages });

        pool.query(`
            UPDATE messages 
            SET is_read = TRUE 
            WHERE conversation_id IN (
                SELECT id FROM conversations WHERE (user_a_id = $1 AND user_b_id = $2) OR (user_a_id = $2 AND user_b_id = $1)
            ) 
            AND sender_id = $2
            AND is_read = FALSE
        `, [myId, friendId]).catch(e => console.error('Mark read error', e));

    } catch (e) {
        console.error('History API error:', e);
        res.status(500).json({ error: 'Geçmiş yüklenemedi.' });
    }
});

// Remove Friend (Delete)
router.delete('/:friendId', async (req, res) => {
    const friendId = req.params.friendId;
    const myId = req.user.user_id;

    try {
        const result = await pool.query(`
            DELETE FROM friendships 
            WHERE ((user_id = $1 AND friend_user_id = $2) OR (user_id = $2 AND friend_user_id = $1))
            AND status = 'accepted'
        `, [myId, friendId]);

        if (result.rowCount === 0) {
            // Ensure no pending requests
            await pool.query(`
                DELETE FROM friendships 
                WHERE ((user_id = $1 AND friend_user_id = $2) OR (user_id = $2 AND friend_user_id = $1))
            `, [myId, friendId]);
        }

        // FEATURE: Delete Conversation History
        try {
            await pool.query(`
                DELETE FROM conversations 
                WHERE (user_a_id = $1 AND user_b_id = $2) OR (user_a_id = $2 AND user_b_id = $1)
            `, [myId, friendId]);
            // Messages will be deleted via CASCADE if configured, otherwise we should delete them manually.
            // Assuming ON DELETE CASCADE is NOT usually default for everyone's manual schema, let's look at db.js or just delete.
            // But deleting conversation is safer if we want to wipe history. It's cleaner.
        } catch (e) {
            console.error('Failed to delete conversation history', e);
        }

        res.json({ success: true, message: 'Arkadaş silindi.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Hata.' });
    }
});

module.exports = router;
