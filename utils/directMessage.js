const DIRECT_MESSAGE_MAX_CODE_POINTS = 2000;
const DIRECT_MESSAGE_MAX_BYTES = 8000;

const normalizeDirectText = (value) => String(value ?? '').normalize('NFC').trim();

const validateDirectText = (value) => {
    if (typeof value !== 'string') return { ok: false, code: 'INVALID_MESSAGE_REQUEST' };
    const text = normalizeDirectText(value);
    if (!text) return { ok: false, code: 'INVALID_MESSAGE_REQUEST' };
    if (Array.from(text).length > DIRECT_MESSAGE_MAX_CODE_POINTS || Buffer.byteLength(text, 'utf8') > DIRECT_MESSAGE_MAX_BYTES) {
        return { ok: false, code: 'MESSAGE_TOO_LONG' };
    }
    return { ok: true, text };
};

const sameImmutablePayload = (row, { conversationId, text }) => (
    String(row?.conversation_id || '') === String(conversationId || '')
    && row?.msg_type === 'direct'
    && normalizeDirectText(row?.text) === text
);

const resolveDirectConversation = async ({ pool, senderId, targetUserId, conversationId }) => {
    const client = await pool.connect();
    const pairKey = [String(senderId), String(targetUserId)].sort().join(':');
    try {
        await client.query('BEGIN');
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`direct:${pairKey}`]);
        const existing = await client.query(`
            SELECT id FROM conversations
            WHERE ((user_a_id = $1 AND user_b_id = $2) OR (user_a_id = $2 AND user_b_id = $1))
            ORDER BY started_at DESC, id ASC
            LIMIT 1
        `, [senderId, targetUserId]);
        let resolved = existing.rows[0]?.id || null;
        if (!resolved) {
            const inserted = await client.query(
                'INSERT INTO conversations (id, user_a_id, user_b_id) VALUES ($1, $2, $3) RETURNING id',
                [conversationId, senderId, targetUserId]
            );
            resolved = inserted.rows[0].id;
        }
        await client.query('COMMIT');
        return resolved;
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
    } finally {
        client.release();
    }
};

const persistDirectMessage = async ({ pool, conversationId, senderId, clientMsgId, text, messageId }) => {
    const insert = await pool.query(`
        INSERT INTO messages (id, conversation_id, sender_id, client_msg_id, text, msg_type)
        VALUES ($1, $2, $3, $4, $5, 'direct')
        ON CONFLICT (sender_id, client_msg_id) WHERE client_msg_id IS NOT NULL DO NOTHING
        RETURNING id, conversation_id, text, msg_type, created_at
    `, [messageId, conversationId, senderId, clientMsgId, text]);

    if (insert.rows.length > 0) return { kind: 'created', row: insert.rows[0] };

    const existing = await pool.query(`
        SELECT id, conversation_id, text, msg_type, created_at
        FROM messages
        WHERE sender_id = $1 AND client_msg_id = $2
        LIMIT 1
    `, [senderId, clientMsgId]);
    const row = existing.rows[0];
    if (!row || !sameImmutablePayload(row, { conversationId, text })) {
        return { kind: 'conflict', row: row || null };
    }
    return { kind: 'replayed', row };
};

const buildDirectMessageAck = ({ clientMsgId, result }) => ({
    type: 'direct_message_ack',
    protocolVersion: 1,
    clientMsgId,
    status: 'persisted',
    idempotency: result.kind,
    serverMessageId: result.row.id,
    conversationId: result.row.conversation_id,
    createdAt: result.row.created_at,
    retryable: false
});

const buildDirectMessageFailure = ({ clientMsgId = null, errorCode, retryable }) => ({
    type: 'direct_message_ack',
    protocolVersion: 1,
    clientMsgId,
    status: 'failed',
    errorCode,
    retryable: Boolean(retryable)
});

module.exports = {
    DIRECT_MESSAGE_MAX_BYTES,
    DIRECT_MESSAGE_MAX_CODE_POINTS,
    buildDirectMessageAck,
    buildDirectMessageFailure,
    normalizeDirectText,
    persistDirectMessage,
    resolveDirectConversation,
    validateDirectText
};
