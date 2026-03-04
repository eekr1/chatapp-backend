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

        if (result.rows.length === 0) return res.status(401).json({ error: 'Oturum gecersiz.' });
        req.user = result.rows[0];
        next();
    } catch (e) {
        res.status(500).json({ error: 'Hata.' });
    }
};

router.use(authenticate);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUuid = (value) => typeof value === 'string' && UUID_RE.test(value);

const removeFriendshipAndConversation = async (db, userAId, userBId) => {
    await db.query(`
        DELETE FROM friendships
        WHERE ((user_id = $1 AND friend_user_id = $2) OR (user_id = $2 AND friend_user_id = $1))
    `, [userAId, userBId]);

    try {
        await db.query(`
            DELETE FROM conversations
            WHERE (user_a_id = $1 AND user_b_id = $2) OR (user_a_id = $2 AND user_b_id = $1)
        `, [userAId, userBId]);
    } catch (e) {
        console.error('Failed to delete conversation history', e);
    }
};

// Send Friend Request
router.post('/request', async (req, res) => {
    const { target_username } = req.body;
    if (!target_username) return res.status(400).json({ error: 'Kullanici adi gerekli.' });

    const myId = req.user.user_id;

    try {
        const targetRes = await pool.query('SELECT id FROM users WHERE username = $1', [target_username.toLowerCase()]);
        const target = targetRes.rows[0];

        if (!target) return res.status(404).json({ error: 'Kullanici bulunamadi.' });
        if (target.id === myId) return res.status(400).json({ error: 'Kendine istek atamazsin.' });

        const blockCheck = await pool.query(`
            SELECT 1 FROM blocks
            WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)
        `, [myId, target.id]);
        if (blockCheck.rows.length > 0) {
            return res.status(403).json({ error: 'Bu kullanici ile etkilesime gecemezsiniz.' });
        }

        const exists = await pool.query(`
            SELECT * FROM friendships
            WHERE (user_id = $1 AND friend_user_id = $2) OR (user_id = $2 AND friend_user_id = $1)
        `, [myId, target.id]);

        if (exists.rows.length > 0) {
            const friendship = exists.rows[0];
            if (friendship.status === 'accepted') {
                return res.status(400).json({ error: 'Zaten arkadassiniz.' });
            }
            if (friendship.status === 'pending') {
                if (friendship.user_id === myId) {
                    return res.status(400).json({ error: 'Istek zaten gonderilmis.' });
                }
                return res.status(400).json({ error: 'Bu kullanici zaten sana istek atmis. Istekleri kontrol et.' });
            }
        }

        await pool.query(
            'INSERT INTO friendships (user_id, friend_user_id, status) VALUES ($1, $2, $3)',
            [myId, target.id, 'pending']
        );

        if (req.notifyUser) {
            req.notifyUser(target.id, { type: 'friend_refresh' });
        }

        res.json({ success: true, message: 'Istek gonderildi.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatasi.' });
    }
});

// List Friends & Requests
router.get('/list', async (req, res) => {
    const myId = req.user.user_id;
    try {
        const result = await pool.query(`
            SELECT
                f.status,
                u.id AS user_id,
                u.username,
                p.display_name,
                p.avatar_url,
                CASE WHEN f.user_id = $1 THEN 'outgoing' ELSE 'incoming' END AS direction
            FROM friendships f
            JOIN users u ON (f.user_id = u.id OR f.friend_user_id = u.id)
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE (f.user_id = $1 OR f.friend_user_id = $1)
            AND u.id != $1
        `, [myId]);

        const unreadRes = await pool.query(`
             SELECT m.sender_id, COUNT(*) AS cnt
             FROM messages m
             JOIN conversations c ON m.conversation_id = c.id
             WHERE m.sender_id != $1
             AND m.is_read = FALSE
             AND (c.user_a_id = $1 OR c.user_b_id = $1)
             GROUP BY m.sender_id
        `, [myId]);

        const unreadMap = {};
        unreadRes.rows.forEach((row) => {
            unreadMap[row.sender_id] = parseInt(row.cnt, 10);
        });

        const friends = result.rows
            .filter((row) => row.status === 'accepted')
            .map((friend) => ({
                ...friend,
                unread_count: unreadMap[friend.user_id] || 0,
                is_online: req.isUserOnline ? req.isUserOnline(friend.user_id) : false
            }));
        const requests = result.rows.filter((row) => row.status === 'pending');

        const incoming = requests.filter((row) => row.direction === 'incoming');
        const outgoing = requests.filter((row) => row.direction === 'outgoing');

        res.json({ success: true, friends, incoming, outgoing });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatasi.' });
    }
});

// List Blocked Users
router.get('/blocked', async (req, res) => {
    const myId = req.user.user_id;
    try {
        const result = await pool.query(`
            SELECT
                b.blocked_id AS user_id,
                u.username,
                p.display_name,
                p.avatar_url,
                b.created_at
            FROM blocks b
            JOIN users u ON u.id = b.blocked_id
            LEFT JOIN profiles p ON p.user_id = u.id
            WHERE b.blocker_id = $1
            ORDER BY b.created_at DESC
        `, [myId]);

        res.json({ success: true, blocked: result.rows });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Sunucu hatasi.' });
    }
});

// Block User
router.post('/block', async (req, res) => {
    const myId = req.user.user_id;
    const { target_user_id } = req.body;

    if (!target_user_id) {
        return res.status(400).json({ error: 'Hedef kullanici gerekli.', code: 'INVALID_TARGET_ID' });
    }
    if (!isUuid(target_user_id)) {
        return res.status(400).json({ error: 'Gecersiz hedef kullanici kimligi.', code: 'INVALID_TARGET_ID' });
    }
    if (target_user_id === myId) {
        return res.status(400).json({ error: 'Kendini engelleyemezsin.', code: 'INVALID_TARGET_ID' });
    }

    const db = await pool.connect();
    try {
        await db.query('BEGIN');

        const targetRes = await db.query('SELECT id FROM users WHERE id = $1', [target_user_id]);
        if (targetRes.rows.length === 0) {
            await db.query('ROLLBACK');
            return res.status(404).json({ error: 'Kullanici bulunamadi.' });
        }

        await db.query(`
            INSERT INTO blocks (blocker_id, blocked_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
        `, [myId, target_user_id]);

        await removeFriendshipAndConversation(db, myId, target_user_id);
        await db.query('COMMIT');

        if (req.notifyUser) {
            req.notifyUser(myId, { type: 'friend_refresh' });
            req.notifyUser(target_user_id, { type: 'friend_refresh' });
        }

        res.json({ success: true, message: 'Kullanici engellendi.' });
    } catch (e) {
        try {
            await db.query('ROLLBACK');
        } catch {
            // Ignore rollback errors.
        }
        console.error('friends:block failed', {
            endpoint: '/friends/block',
            actorUserId: myId,
            targetUserId: target_user_id,
            pgCode: e?.code || null,
            message: e?.message || String(e)
        });

        if (e?.code === '22P02') {
            return res.status(400).json({ error: 'Gecersiz hedef kullanici kimligi.', code: 'INVALID_TARGET_ID' });
        }
        if (e?.code === '42P01') {
            return res.status(500).json({ error: 'Veritabani semasi hazir degil.', code: 'SCHEMA_NOT_READY' });
        }
        res.status(500).json({ error: 'Engelleme islemi su anda tamamlanamadi.', code: 'BLOCK_OPERATION_FAILED' });
    } finally {
        db.release();
    }
});

// Unblock User
router.post('/unblock', async (req, res) => {
    const myId = req.user.user_id;
    const { target_user_id } = req.body;

    if (!target_user_id) {
        return res.status(400).json({ error: 'Hedef kullanici gerekli.', code: 'INVALID_TARGET_ID' });
    }
    if (!isUuid(target_user_id)) {
        return res.status(400).json({ error: 'Gecersiz hedef kullanici kimligi.', code: 'INVALID_TARGET_ID' });
    }
    if (target_user_id === myId) {
        return res.status(400).json({ error: 'Gecersiz islem.', code: 'INVALID_TARGET_ID' });
    }

    try {
        await pool.query(
            'DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2',
            [myId, target_user_id]
        );

        if (req.notifyUser) {
            req.notifyUser(myId, { type: 'friend_refresh' });
            req.notifyUser(target_user_id, { type: 'friend_refresh' });
        }

        res.json({ success: true, message: 'Engel kaldirildi.' });
    } catch (e) {
        console.error('friends:unblock failed', {
            endpoint: '/friends/unblock',
            actorUserId: myId,
            targetUserId: target_user_id,
            pgCode: e?.code || null,
            message: e?.message || String(e)
        });

        if (e?.code === '22P02') {
            return res.status(400).json({ error: 'Gecersiz hedef kullanici kimligi.', code: 'INVALID_TARGET_ID' });
        }
        if (e?.code === '42P01') {
            return res.status(500).json({ error: 'Veritabani semasi hazir degil.', code: 'SCHEMA_NOT_READY' });
        }
        res.status(500).json({ error: 'Engel kaldirma islemi su anda tamamlanamadi.', code: 'BLOCK_OPERATION_FAILED' });
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

        if (result.rows.length === 0) return res.status(404).json({ error: 'Istek bulunamadi.' });

        if (req.notifyUser) {
            req.notifyUser(request_user_id, { type: 'friend_refresh' });
            req.notifyUser(myId, { type: 'friend_refresh' });
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
        await pool.query(`
            DELETE FROM friendships
            WHERE ((user_id = $1 AND friend_user_id = $2) OR (user_id = $2 AND friend_user_id = $1))
        `, [myId, target_user_id]);

        res.json({ success: true, message: 'Iliski silindi / reddedildi.' });
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

        const messages = await Promise.all(msgRes.rows.map(async (msg) => {
            let mediaExpired = false;
            if (msg.msg_type === 'image' && msg.media_id) {
                const check = await pool.query('SELECT 1 FROM ephemeral_media WHERE id = $1', [msg.media_id]);
                mediaExpired = check.rows.length === 0;
            }
            return {
                from: msg.sender_id === myId ? 'me' : 'peer',
                text: msg.text,
                msgType: msg.msg_type,
                clientMsgId: msg.client_msg_id,
                mediaId: msg.media_id,
                mediaExpired,
                createdAt: msg.created_at,
                timestamp: new Date(msg.created_at).getTime(),
                isRead: msg.is_read
            };
        }));

        res.json({ success: true, messages });

        pool.query(`
            UPDATE messages
            SET is_read = TRUE
            WHERE conversation_id IN (
                SELECT id FROM conversations
                WHERE (user_a_id = $1 AND user_b_id = $2) OR (user_a_id = $2 AND user_b_id = $1)
            )
            AND sender_id = $2
            AND is_read = FALSE
        `, [myId, friendId]).catch((e) => console.error('Mark read error', e));
    } catch (e) {
        console.error('History API error:', e);
        res.status(500).json({ error: 'Gecmis yuklenemedi.' });
    }
});

// Remove Friend (Delete only, no block)
router.delete('/:friendId', async (req, res) => {
    const friendId = req.params.friendId;
    const myId = req.user.user_id;

    try {
        await removeFriendshipAndConversation(pool, myId, friendId);
        res.json({ success: true, message: 'Arkadas silindi.' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Hata.' });
    }
});

module.exports = router;
