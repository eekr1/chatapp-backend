const test = require('node:test');
const assert = require('node:assert/strict');
const {
    MAX_MEDIA_BYTES,
    validateImageDataUrl,
    persistDirectImage,
    consumeImage,
    cleanupExpiredMedia
} = require('../utils/mediaLifecycle');

const pngDataUrl = (width = 32, height = 24) => {
    const bytes = Buffer.alloc(24);
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(bytes, 0);
    bytes.write('IHDR', 12, 'ascii');
    bytes.writeUInt32BE(width, 16);
    bytes.writeUInt32BE(height, 20);
    return `data:image/png;base64,${bytes.toString('base64')}`;
};

test('Wave 11 validates magic bytes, MIME and approved dimensions', () => {
    const valid = validateImageDataUrl(pngDataUrl());
    assert.equal(valid.ok, true);
    assert.equal(valid.contentType, 'image/png');
    assert.equal(valid.width, 32);
    assert.equal(valid.height, 24);
    assert.equal(validateImageDataUrl(pngDataUrl(4097, 1)).code, 'MEDIA_DIMENSIONS_EXCEEDED');
    assert.equal(validateImageDataUrl(pngDataUrl(4096, 4096)).ok, true);
    assert.equal(validateImageDataUrl('data:image/jpeg;base64,' + pngDataUrl().split(',')[1]).code, 'MEDIA_INVALID_TYPE');
    assert.equal(validateImageDataUrl('data:image/svg+xml;base64,PHN2Zy8+').code, 'MEDIA_INVALID_TYPE');
});

test('Wave 11 enforces decoded byte limit', () => {
    const oversized = Buffer.alloc(MAX_MEDIA_BYTES + 1).toString('base64');
    assert.equal(validateImageDataUrl(`data:image/png;base64,${oversized}`).code, 'MEDIA_TOO_LARGE');
});

test('Wave 11 consume is one atomic transition with explicit terminal status', async () => {
    let call = 0;
    const pool = { query: async () => {
        call += 1;
        if (call === 1) return { rows: [] };
        return { rows: [{ status: 'consumed', expires_at: new Date(Date.now() + 1000), revision: 2 }] };
    } };
    const result = await consumeImage({ pool, mediaId: 'm1', receiverId: 'u1' });
    assert.deepEqual(result, { ok: false, code: 'MEDIA_ALREADY_CONSUMED', status: 'consumed', revision: 2 });
});

test('Wave 11 rejects client id reuse across text and media payloads', async () => {
    let released = false;
    const client = {
        query: async (sql) => {
            if (sql === 'BEGIN' || sql === 'ROLLBACK') return { rows: [] };
            return { rows: [{ id: 'text-1', conversation_id: 'conversation-1', media_id: null, content_fingerprint: null }] };
        },
        release: () => { released = true; }
    };
    const pool = { connect: async () => client };
    await assert.rejects(
        persistDirectImage({
            pool,
            senderId: 'sender', receiverId: 'receiver', conversationId: 'conversation-1',
            clientMsgId: 'same-id', imageData: pngDataUrl(), validated: validateImageDataUrl(pngDataUrl())
        }),
        (error) => error.code === 'IDEMPOTENCY_CONFLICT'
    );
    assert.equal(released, true);
});

test('Wave 11 treats a changed media target as an idempotency conflict', async () => {
    const validated = validateImageDataUrl(pngDataUrl());
    const client = {
        query: async (sql) => {
            if (sql === 'BEGIN' || sql === 'ROLLBACK') return { rows: [] };
            return { rows: [{ id: 'image-1', conversation_id: 'conversation-1', media_id: 'media-1', receiver_id: 'other-receiver', content_fingerprint: validated.fingerprint }] };
        },
        release: () => {}
    };
    await assert.rejects(
        persistDirectImage({ pool: { connect: async () => client }, senderId: 'sender', receiverId: 'receiver', conversationId: 'conversation-1', clientMsgId: 'same-id', imageData: validated.dataUrl, validated }),
        (error) => error.code === 'IDEMPOTENCY_CONFLICT'
    );
});

test('Wave 11 cleanup defaults to dry-run and caps batch size', async () => {
    let params;
    const pool = { query: async (_sql, values) => { params = values; return { rows: [{ count: 7 }] }; } };
    const result = await cleanupExpiredMedia({ pool, batchSize: 1000 });
    assert.deepEqual(result, { dryRun: true, affected: 7 });
    assert.deepEqual(params, [100]);
});

test('Wave 11 execute cleanup is bounded and advisory locked', async () => {
    let sql = '';
    const pool = { query: async (query) => { sql = query; return { rowCount: 0, rows: [] }; } };
    await cleanupExpiredMedia({ pool, dryRun: false, batchSize: 100 });
    assert.match(sql, /pg_try_advisory_xact_lock/);
    assert.match(sql, /FOR UPDATE SKIP LOCKED/);
});
