const crypto = require('crypto');

const MEDIA_POLICY_VERSION = 'talkx-media-policy-wave11-v1';
const MAX_MEDIA_BYTES = 2 * 1024 * 1024;
const MAX_MEDIA_WIDTH = 4096;
const MAX_MEDIA_HEIGHT = 4096;
const MAX_MEDIA_PIXELS = 16 * 1024 * 1024;
const MEDIA_TTL_DAYS = 7;
const CLEANUP_BATCH_SIZE = 100;

const readJpegDimensions = (buffer) => {
    let offset = 2;
    while (offset + 9 < buffer.length) {
        if (buffer[offset] !== 0xff) return null;
        const marker = buffer[offset + 1];
        if (marker === 0xd9 || marker === 0xda) return null;
        const length = buffer.readUInt16BE(offset + 2);
        if (length < 2 || offset + length + 2 > buffer.length) return null;
        if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
            return { height: buffer.readUInt16BE(offset + 5), width: buffer.readUInt16BE(offset + 7) };
        }
        offset += length + 2;
    }
    return null;
};

const stripJpegExif = (buffer) => {
    const chunks = [buffer.subarray(0, 2)];
    let offset = 2;
    while (offset + 3 < buffer.length) {
        if (buffer[offset] !== 0xff) return buffer;
        const marker = buffer[offset + 1];
        if (marker === 0xda) {
            chunks.push(buffer.subarray(offset));
            return Buffer.concat(chunks);
        }
        const length = buffer.readUInt16BE(offset + 2);
        if (length < 2 || offset + length + 2 > buffer.length) return buffer;
        if (marker !== 0xe1) chunks.push(buffer.subarray(offset, offset + length + 2));
        offset += length + 2;
    }
    return buffer;
};

const inspectImage = (buffer) => {
    if (buffer.length >= 24 && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
        if (buffer.toString('ascii', 12, 16) !== 'IHDR') return null;
        return { contentType: 'image/png', width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
    }
    if (buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') {
        const kind = buffer.toString('ascii', 12, 16);
        if (kind === 'VP8X' && buffer.length >= 30) return { contentType: 'image/webp', width: 1 + buffer.readUIntLE(24, 3), height: 1 + buffer.readUIntLE(27, 3) };
        if (kind === 'VP8 ' && buffer.length >= 30 && buffer[23] === 0x9d && buffer[24] === 0x01 && buffer[25] === 0x2a) return { contentType: 'image/webp', width: buffer.readUInt16LE(26) & 0x3fff, height: buffer.readUInt16LE(28) & 0x3fff };
        if (kind === 'VP8L' && buffer.length >= 25 && buffer[20] === 0x2f) {
            const bits = buffer.readUInt32LE(21);
            return { contentType: 'image/webp', width: 1 + (bits & 0x3fff), height: 1 + ((bits >>> 14) & 0x3fff) };
        }
        return null;
    }
    if (buffer.length >= 4 && buffer[0] === 0xff && buffer[1] === 0xd8) {
        const dimensions = readJpegDimensions(buffer);
        return dimensions ? { contentType: 'image/jpeg', ...dimensions } : null;
    }
    return null;
};

const validateImageDataUrl = (dataUrl) => {
    if (typeof dataUrl !== 'string') return { ok: false, code: 'INVALID_IMAGE' };
    const match = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})$/.exec(dataUrl);
    if (!match || match[2].length % 4 !== 0) return { ok: false, code: 'MEDIA_INVALID_TYPE' };
    let buffer;
    try { buffer = Buffer.from(match[2], 'base64'); } catch { return { ok: false, code: 'INVALID_IMAGE' }; }
    if (!buffer.length || buffer.length > MAX_MEDIA_BYTES) return { ok: false, code: 'MEDIA_TOO_LARGE' };
    if (buffer.toString('base64') !== match[2]) return { ok: false, code: 'INVALID_IMAGE' };
    const inspected = inspectImage(buffer);
    if (!inspected || inspected.contentType !== match[1]) return { ok: false, code: 'MEDIA_INVALID_TYPE' };
    const { width, height } = inspected;
    if (!width || !height || width > MAX_MEDIA_WIDTH || height > MAX_MEDIA_HEIGHT || width * height > MAX_MEDIA_PIXELS) return { ok: false, code: 'MEDIA_DIMENSIONS_EXCEEDED' };
    const sanitized = inspected.contentType === 'image/jpeg' ? stripJpegExif(buffer) : buffer;
    return {
        ok: true,
        buffer: sanitized,
        dataUrl: `data:${inspected.contentType};base64,${sanitized.toString('base64')}`,
        contentType: inspected.contentType,
        width,
        height,
        byteSize: sanitized.length,
        fingerprint: crypto.createHash('sha256').update(sanitized).digest('hex')
    };
};

const persistDirectImage = async ({ pool, senderId, receiverId, conversationId, clientMsgId, imageData, validated }) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const existing = await client.query(
            'SELECT m.id,m.conversation_id,m.media_id,em.receiver_id,em.content_fingerprint,em.status,em.revision,em.expires_at FROM messages m LEFT JOIN ephemeral_media em ON em.id=m.media_id WHERE m.sender_id=$1 AND m.client_msg_id=$2 LIMIT 1',
            [senderId, clientMsgId]
        );
        if (existing.rows.length) {
            const row = existing.rows[0];
            if (!row.media_id || row.receiver_id !== receiverId || row.content_fingerprint !== validated.fingerprint) {
                const error = new Error('Idempotency key reused with different media.');
                error.code = 'IDEMPOTENCY_CONFLICT';
                throw error;
            }
            await client.query('COMMIT');
            return { duplicate: true, mediaId: row.media_id, serverMessageId: row.id, conversationId: row.conversation_id, mediaStatus: row.status, revision: row.revision, expiresAt: row.expires_at };
        }
        const media = await client.query(
            `INSERT INTO ephemeral_media
              (sender_id,receiver_id,conversation_id,client_msg_id,media_data,content_type,byte_size,width,height,content_fingerprint,status,expires_at,policy_version)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'available',NOW() + ($11::text || ' days')::interval,$12) RETURNING id,expires_at,revision`,
            [senderId, receiverId, conversationId, clientMsgId, imageData, validated.contentType, validated.byteSize, validated.width, validated.height, validated.fingerprint, MEDIA_TTL_DAYS, MEDIA_POLICY_VERSION]
        );
        const message = await client.query(
            `INSERT INTO messages (conversation_id,sender_id,client_msg_id,text,msg_type,media_id)
             VALUES ($1,$2,$3,$4,'image',$5) RETURNING id`,
            [conversationId, senderId, clientMsgId, 'Photo sent', media.rows[0].id]
        );
        await client.query('UPDATE ephemeral_media SET message_id=$2 WHERE id=$1', [media.rows[0].id, message.rows[0].id]);
        await client.query('COMMIT');
        return { duplicate: false, mediaId: media.rows[0].id, serverMessageId: message.rows[0].id, conversationId, mediaStatus: 'available', revision: media.rows[0].revision, expiresAt: media.rows[0].expires_at };
    } catch (error) {
        await client.query('ROLLBACK');
        if (error?.code === '23505') {
            const replay = await pool.query(
                'SELECT m.id,m.conversation_id,m.media_id,em.receiver_id,em.content_fingerprint,em.status,em.revision,em.expires_at FROM messages m LEFT JOIN ephemeral_media em ON em.id=m.media_id WHERE m.sender_id=$1 AND m.client_msg_id=$2 LIMIT 1',
                [senderId, clientMsgId]
            );
            if (replay.rows.length && replay.rows[0].media_id && replay.rows[0].receiver_id === receiverId && replay.rows[0].content_fingerprint === validated.fingerprint) {
                const row = replay.rows[0];
                return { duplicate: true, mediaId: row.media_id, serverMessageId: row.id, conversationId: row.conversation_id, mediaStatus: row.status, revision: row.revision, expiresAt: row.expires_at };
            }
            if (replay.rows.length) error.code = 'IDEMPOTENCY_CONFLICT';
        }
        throw error;
    } finally {
        client.release();
    }
};

const consumeImage = async ({ pool, mediaId, receiverId }) => {
    const result = await pool.query(
        `WITH candidate AS (
           SELECT id,media_data,content_type FROM ephemeral_media
           WHERE id=$1 AND receiver_id=$2 AND status='available' AND expires_at>NOW()
           FOR UPDATE
         )
         UPDATE ephemeral_media em
         SET status='consumed',consumed_at=NOW(),media_data=NULL,purged_at=NOW(),revision=revision+1
         FROM candidate WHERE em.id=candidate.id
         RETURNING candidate.media_data,candidate.content_type,em.revision`,
        [mediaId, receiverId]
    );
    if (result.rows.length) return { ok: true, ...result.rows[0] };
    const state = await pool.query('SELECT status,expires_at,revision FROM ephemeral_media WHERE id=$1 AND receiver_id=$2', [mediaId, receiverId]);
    if (!state.rows.length) return { ok: false, code: 'MEDIA_NOT_FOUND' };
    const row = state.rows[0];
    if (row.status === 'available' && new Date(row.expires_at).getTime() <= Date.now()) return { ok: false, code: 'MEDIA_EXPIRED', status: 'expired', revision: row.revision };
    if (row.status === 'quarantined') return { ok: false, code: 'MEDIA_QUARANTINED', status: 'quarantined', revision: row.revision };
    return { ok: false, code: row.status === 'consumed' ? 'MEDIA_ALREADY_CONSUMED' : 'MEDIA_UNAVAILABLE', status: row.status, revision: row.revision };
};

const cleanupExpiredMedia = async ({ pool, dryRun = true, batchSize = CLEANUP_BATCH_SIZE } = {}) => {
    const limit = Math.max(1, Math.min(CLEANUP_BATCH_SIZE, Number(batchSize) || CLEANUP_BATCH_SIZE));
    if (dryRun) {
        const result = await pool.query(
            `SELECT COUNT(*)::int AS count FROM
             (SELECT id FROM ephemeral_media WHERE expires_at<=NOW() AND status='available' LIMIT $1) q`,
            [limit]
        );
        return { dryRun: true, affected: Number(result.rows[0]?.count || 0) };
    }
    const result = await pool.query(
        `WITH candidates AS (
           SELECT id FROM ephemeral_media
           WHERE expires_at<=NOW() AND status='available'
           ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED
         ), lock AS (SELECT pg_try_advisory_xact_lock(118011) AS acquired)
         UPDATE ephemeral_media em
         SET status='expired',media_data=NULL,purged_at=NOW(),revision=revision+1
         FROM candidates,lock WHERE lock.acquired AND em.id=candidates.id RETURNING em.id`,
        [limit]
    );
    return { dryRun: false, affected: result.rowCount || 0 };
};

module.exports = {
    MEDIA_POLICY_VERSION,
    MAX_MEDIA_BYTES,
    MAX_MEDIA_WIDTH,
    MAX_MEDIA_HEIGHT,
    MAX_MEDIA_PIXELS,
    MEDIA_TTL_DAYS,
    CLEANUP_BATCH_SIZE,
    validateImageDataUrl,
    persistDirectImage,
    consumeImage,
    cleanupExpiredMedia
};
