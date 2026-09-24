const express = require('express');
const router = express.Router();
const { pool } = require('../db');
const { calculateLegalStatus } = require('../utils/legalAcceptance');
const { sendApiError } = require('../utils/i18n');
const { authenticate: authenticateSession } = require('../utils/sessionService');

const authenticate = async (req, res, next) => {
    return authenticateSession(req, res, async () => {
        try {
            const legalStatus = await calculateLegalStatus(pool, req.user.user_id);
            if (legalStatus.requiresReaccept) {
                return sendApiError(req, res, 428, 'LEGAL_REACCEPT_REQUIRED', {}, 'errors.LEGAL_REACCEPT_REQUIRED', {
                    metadata: { required_versions: legalStatus.required, accepted_versions: legalStatus.accepted }
                });
            }
            return next();
        } catch { return sendApiError(req, res, 500, 'SERVER_ERROR'); }
    });
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
    const cleanTargetUsername = typeof target_username === 'string' ? target_username.trim().toLowerCase() : '';
    if (cleanTargetUsername.length < 3 || cleanTargetUsername.length > 32 || !/^[a-z0-9_]+$/.test(cleanTargetUsername)) {
        return sendApiError(req, res, 400, 'INVALID_INPUT');
    }

    const myId = req.user.user_id;

    try {
        const targetRes = await pool.query('SELECT id FROM users WHERE username = $1', [cleanTargetUsername]);
        const target = targetRes.rows[0];

        if (!target) return sendApiError(req, res, 404, 'USER_NOT_FOUND');
        if (target.id === myId) return sendApiError(req, res, 400, 'INVALID_INPUT');

        const blockCheck = await pool.query(`
            SELECT 1 FROM blocks
            WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)
        `, [myId, target.id]);
        if (blockCheck.rows.length > 0) {
            return sendApiError(req, res, 403, 'INVALID_INPUT');
        }

        const exists = await pool.query(`
            SELECT * FROM friendships
            WHERE (user_id = $1 AND friend_user_id = $2) OR (user_id = $2 AND friend_user_id = $1)
        `, [myId, target.id]);

        if (exists.rows.length > 0) {
            const friendship = exists.rows[0];
            if (friendship.status === 'accepted') {
                return sendApiError(req, res, 400, 'ALREADY_FRIENDS');
            }
            if (friendship.status === 'pending') {
                if (friendship.user_id === myId) {
                    return sendApiError(req, res, 400, 'FRIEND_REQUEST_ALREADY_SENT');
                }
                return sendApiError(req, res, 400, 'FRIEND_REQUEST_ALREADY_RECEIVED');
            }
        }

        const insertResult = await pool.query(
            'INSERT INTO friendships (user_id, friend_user_id, status) VALUES ($1, $2, $3) RETURNING created_at',
            [myId, target.id, 'pending']
        );

        const senderProfileRes = await pool.query(
            'SELECT display_name FROM profiles WHERE user_id = $1 LIMIT 1',
            [myId]
        );
        const fromDisplayName = String(senderProfileRes.rows[0]?.display_name || req.user.username || '').trim() || String(req.user.username || '').trim();
        const sentAt = insertResult.rows[0]?.created_at
            ? new Date(insertResult.rows[0].created_at).toISOString()
            : new Date().toISOString();

        if (req.notifyUser) {
            req.notifyUser(target.id, { type: 'friend_refresh' });
            req.notifyUser(target.id, {
                type: 'friend_request_incoming',
                request_user_id: myId,
                from_username: req.user.username,
                from_display_name: fromDisplayName,
                sent_at: sentAt
            });
        }

        res.json({ success: true, code: 'FRIEND_REQUEST_SENT' });
    } catch (e) {
        console.error(e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
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
                u.last_seen_at,
                p.display_name,
                p.avatar_url,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM connection_leases cl
                        WHERE cl.user_id = u.id AND cl.expires_at > NOW()
                    ) THEN 'online'
                    ELSE 'offline'
                END AS presence_state,
                NOW() AS presence_observed_at,
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
                is_online: friend.presence_state === 'online'
            }));
        const requests = result.rows.filter((row) => row.status === 'pending');

        const incoming = requests.filter((row) => row.direction === 'incoming');
        const outgoing = requests.filter((row) => row.direction === 'outgoing');

        res.json({ success: true, friends, incoming, outgoing });
    } catch (e) {
        console.error(e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
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
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// Block User
router.post('/block', async (req, res) => {
    const myId = req.user.user_id;
    const { target_user_id } = req.body;

    if (!target_user_id) {
        return sendApiError(req, res, 400, 'INVALID_TARGET_ID');
    }
    if (!isUuid(target_user_id)) {
        return sendApiError(req, res, 400, 'INVALID_TARGET_ID');
    }
    if (target_user_id === myId) {
        return sendApiError(req, res, 400, 'SELF_ACTION_NOT_ALLOWED');
    }

    const db = await pool.connect();
    try {
        await db.query('BEGIN');

        const targetRes = await db.query('SELECT id FROM users WHERE id = $1', [target_user_id]);
        if (targetRes.rows.length === 0) {
            await db.query('ROLLBACK');
            return sendApiError(req, res, 404, 'USER_NOT_FOUND');
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

        res.json({ success: true, code: 'BLOCKED' });
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
            return sendApiError(req, res, 400, 'INVALID_TARGET_ID');
        }
        if (e?.code === '42P01') {
            return sendApiError(req, res, 500, 'SCHEMA_NOT_READY');
        }
        if (e?.code === '23503') {
            return sendApiError(req, res, 500, 'SCHEMA_NOT_READY');
        }
        return sendApiError(req, res, 500, 'BLOCK_OPERATION_FAILED');
    } finally {
        db.release();
    }
});

// Unblock User
router.post('/unblock', async (req, res) => {
    const myId = req.user.user_id;
    const { target_user_id } = req.body;

    if (!target_user_id) {
        return sendApiError(req, res, 400, 'INVALID_TARGET_ID');
    }
    if (!isUuid(target_user_id)) {
        return sendApiError(req, res, 400, 'INVALID_TARGET_ID');
    }
    if (target_user_id === myId) {
        return sendApiError(req, res, 400, 'SELF_ACTION_NOT_ALLOWED');
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

        res.json({ success: true, code: 'UNBLOCKED' });
    } catch (e) {
        console.error('friends:unblock failed', {
            endpoint: '/friends/unblock',
            actorUserId: myId,
            targetUserId: target_user_id,
            pgCode: e?.code || null,
            message: e?.message || String(e)
        });

        if (e?.code === '22P02') {
            return sendApiError(req, res, 400, 'INVALID_TARGET_ID');
        }
        if (e?.code === '42P01') {
            return sendApiError(req, res, 500, 'SCHEMA_NOT_READY');
        }
        if (e?.code === '23503') {
            return sendApiError(req, res, 500, 'SCHEMA_NOT_READY');
        }
        return sendApiError(req, res, 500, 'BLOCK_OPERATION_FAILED');
    }
});

// Accept Request
router.post('/accept', async (req, res) => {
    const { request_user_id } = req.body;
    const myId = req.user.user_id;
    if (!isUuid(request_user_id)) return sendApiError(req, res, 400, 'INVALID_TARGET_ID');

    try {
        const result = await pool.query(`
            UPDATE friendships
            SET status = 'accepted', updated_at = NOW()
            WHERE user_id = $1 AND friend_user_id = $2 AND status = 'pending'
            RETURNING *
        `, [request_user_id, myId]);

        if (result.rows.length === 0) return sendApiError(req, res, 404, 'REQUEST_NOT_FOUND');

        if (req.notifyUser) {
            req.notifyUser(request_user_id, { type: 'friend_refresh' });
            req.notifyUser(myId, { type: 'friend_refresh' });
        }

        res.json({ success: true, code: 'REQUEST_ACCEPTED' });
    } catch (e) {
        console.error(e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// Reject Request
router.post('/reject', async (req, res) => {
    const { target_user_id } = req.body;
    const myId = req.user.user_id;
    if (!isUuid(target_user_id)) return sendApiError(req, res, 400, 'INVALID_TARGET_ID');

    try {
        await pool.query(`
            DELETE FROM friendships
            WHERE ((user_id = $1 AND friend_user_id = $2) OR (user_id = $2 AND friend_user_id = $1))
        `, [myId, target_user_id]);

        res.json({ success: true, code: 'REQUEST_REJECTED' });
    } catch (e) {
        console.error(e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// GET /history/:friendId
router.get('/history/:friendId', async (req, res) => {
    const myId = req.user.user_id;
    const friendId = req.params.friendId;

    try {
        const msgRes = await pool.query(`
            SELECT m.id, m.conversation_id, m.sender_id, m.client_msg_id, m.text, m.msg_type, m.created_at, m.is_read, m.media_id,
                   em.status AS media_status, em.expires_at AS media_expires_at
            FROM messages m
            JOIN conversations c ON m.conversation_id = c.id
            LEFT JOIN ephemeral_media em ON em.id = m.media_id
            WHERE ((c.user_a_id = $1 AND c.user_b_id = $2) OR (c.user_a_id = $2 AND c.user_b_id = $1))
            AND m.msg_type IN ('direct', 'image')
            ORDER BY m.created_at ASC, m.id ASC
        `, [myId, friendId]);

        if (process.env.NODE_ENV !== 'production') {
            console.log(`[DEBUG] History for ${myId}<->${friendId} found ${msgRes.rows.length} messages.`);
        }

        const messages = msgRes.rows.map((msg) => {
            const mediaStatus = msg.msg_type === 'image'
                ? (msg.media_status || 'expired')
                : null;
            const mediaExpired = msg.msg_type === 'image'
                && (mediaStatus !== 'available' || (msg.media_expires_at && new Date(msg.media_expires_at).getTime() <= Date.now()));
            return {
                from: msg.sender_id === myId ? 'me' : 'peer',
                text: msg.text,
                msgType: msg.msg_type,
                clientMsgId: msg.client_msg_id,
                serverMessageId: msg.id,
                conversationId: msg.conversation_id,
                mediaId: msg.media_id,
                mediaStatus: mediaExpired && mediaStatus === 'available' ? 'expired' : mediaStatus,
                mediaExpired,
                createdAt: msg.created_at,
                timestamp: new Date(msg.created_at).getTime(),
                isRead: msg.is_read
            };
        });

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
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

// Remove Friend (Delete only, no block)
router.delete('/:friendId', async (req, res) => {
    const friendId = req.params.friendId;
    const myId = req.user.user_id;

    try {
        await removeFriendshipAndConversation(pool, myId, friendId);
        res.json({ success: true, code: 'FRIEND_DELETED' });
    } catch (e) {
        console.error(e);
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
});

module.exports = router;

