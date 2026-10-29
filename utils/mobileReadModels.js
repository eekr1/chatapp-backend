const listConversations = async (pool, userId, { limit = 30, before = null, query = '' } = {}) => {
    const size = Math.min(50, Math.max(1, Math.floor(Number(limit) || 30)));
    let cursor = null;
    if (before) {
        try { cursor = JSON.parse(Buffer.from(String(before), 'base64url').toString()); } catch { /* validated below */ }
        if (!cursor || !Number.isFinite(Date.parse(cursor.at)) || !/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(cursor.id)) throw Object.assign(new Error('Invalid cursor'), { code: 'INVALID_INPUT' });
    }
    const search = String(query).trim().slice(0, 80).replace(/[\\%_]/g, '\\$&');
    const result = await pool.query(`
        WITH accepted AS (
            SELECT DISTINCT CASE WHEN f.user_id = $1 THEN f.friend_user_id ELSE f.user_id END AS friend_id
            FROM friendships f WHERE (f.user_id = $1 OR f.friend_user_id = $1) AND f.status = 'accepted'
        ), summaries AS (
            SELECT u.id AS user_id, u.username, p.display_name, p.avatar_url,
                lm.created_at AS last_message_at, lm.id AS last_message_id,
                CASE WHEN lm.msg_type = 'image' THEN NULL ELSE LEFT(lm.text, 180) END AS last_message,
                lm.msg_type AS last_message_type,
                EXISTS (SELECT 1 FROM connection_leases cl WHERE cl.user_id = u.id AND cl.expires_at > NOW()) AS is_online,
                u.last_seen_at, NOW() AS presence_observed_at,
                (SELECT COUNT(*)::int FROM messages m JOIN conversations c ON c.id = m.conversation_id
                  WHERE ((c.user_a_id = $1 AND c.user_b_id = u.id) OR (c.user_b_id = $1 AND c.user_a_id = u.id))
                    AND m.sender_id = u.id AND NOT m.is_read AND m.msg_type IN ('direct','image')) AS unread_count
            FROM accepted a JOIN users u ON u.id = a.friend_id LEFT JOIN profiles p ON p.user_id = u.id
            JOIN LATERAL (
                SELECT m.id, m.text, m.msg_type, m.created_at FROM messages m JOIN conversations c ON c.id = m.conversation_id
                WHERE ((c.user_a_id = $1 AND c.user_b_id = u.id) OR (c.user_b_id = $1 AND c.user_a_id = u.id))
                    AND m.msg_type IN ('direct','image') ORDER BY m.created_at DESC, m.id DESC LIMIT 1
            ) lm ON TRUE
            WHERE NOT EXISTS (SELECT 1 FROM blocks b
                WHERE ((b.blocker_id = $1 AND b.blocked_id = u.id) OR (b.blocked_id = $1 AND b.blocker_id = u.id)))
                AND ($4 = '' OR COALESCE(p.display_name,'') ILIKE '%' || $4 || '%' ESCAPE '\\' OR u.username ILIKE '%' || $4 || '%' ESCAPE '\\')
        ) SELECT *, CASE WHEN is_online THEN 'online' ELSE 'offline' END AS presence_state FROM summaries
        WHERE ($2::timestamptz IS NULL OR (last_message_at, user_id) < ($2::timestamptz, $5::uuid))
        ORDER BY last_message_at DESC, user_id DESC LIMIT $3`, [userId, cursor ? new Date(cursor.at).toISOString() : null, size + 1, search, cursor?.id || null]);
    const rows = result.rows;
    return { conversations: rows.slice(0, size), hasMore: rows.length > size, nextCursor: rows.length > size ? Buffer.from(JSON.stringify({ at:rows[size - 1].last_message_at, id:rows[size - 1].user_id })).toString('base64url') : null };
};

const getProfileSummary = async (pool, userId) => {
    const result = await pool.query(`SELECT
        (SELECT COUNT(DISTINCT CASE WHEN f.user_id = $1 THEN f.friend_user_id ELSE f.user_id END)::int
          FROM friendships f WHERE (f.user_id = $1 OR f.friend_user_id = $1) AND f.status = 'accepted') AS friends,
        (SELECT COUNT(*)::int FROM conversations c WHERE (c.user_a_id = $1 OR c.user_b_id = $1)
          AND (c.match_id IS NOT NULL OR EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id AND m.msg_type IN ('direct','image')))) AS chats,
        (SELECT COUNT(DISTINCT (created_at AT TIME ZONE 'Europe/Istanbul')::date)::int FROM (
          SELECT created_at FROM behavior_events WHERE user_id = $1 AND event_name IN ('match_search_started','chat_started')
          UNION ALL SELECT created_at FROM messages WHERE sender_id = $1 AND msg_type IN ('direct','image')
        ) activity) AS active_days,
        (SELECT MIN(created_at) FROM behavior_events WHERE user_id = $1
          AND event_name IN ('match_search_started','chat_started')) AS observed_since`, [userId]);
    return { ...result.rows[0], activityScope: 'recorded_activity', timezone: 'Europe/Istanbul' };
};
const markConversationMessageRead = async (pool, userId, peerId, messageId) => {
    const result = await pool.query(`UPDATE messages m SET is_read = TRUE
        FROM conversations c WHERE m.conversation_id = c.id AND m.id = $3 AND m.sender_id = $2
        AND ((c.user_a_id = $1 AND c.user_b_id = $2) OR (c.user_b_id = $1 AND c.user_a_id = $2))
        AND m.msg_type IN ('direct','image') AND NOT m.is_read
        AND EXISTS (SELECT 1 FROM friendships f WHERE f.status = 'accepted'
            AND ((f.user_id = $1 AND f.friend_user_id = $2) OR (f.user_id = $2 AND f.friend_user_id = $1)))
        AND NOT EXISTS (SELECT 1 FROM blocks b WHERE
            (b.blocker_id = $1 AND b.blocked_id = $2) OR (b.blocker_id = $2 AND b.blocked_id = $1))
        RETURNING m.id`, [userId, peerId, messageId]);
    return result.rows.length > 0;
};
module.exports = { listConversations, getProfileSummary, markConversationMessageRead };
