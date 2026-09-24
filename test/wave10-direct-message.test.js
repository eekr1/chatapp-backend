const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
    buildDirectMessageAck,
    buildDirectMessageFailure,
    persistDirectMessage,
    resolveDirectConversation,
    validateDirectText
} = require('../utils/directMessage');
const { validateWsEvent } = require('../utils/wave01Security');

const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

test('direct text contract normalizes Unicode and enforces code point and byte bounds', () => {
    assert.deepEqual(validateDirectText('  e\u0301  '), { ok: true, text: 'é' });
    assert.equal(validateDirectText('😀'.repeat(2000)).ok, true);
    assert.equal(validateDirectText('😀'.repeat(2001)).code, 'MESSAGE_TOO_LONG');
    assert.equal(validateWsEvent({
        type: 'direct_message',
        protocolVersion: 1,
        targetUserId: uuid(1),
        text: 'hello',
        clientMsgId: uuid(2)
    }).ok, true);
    assert.equal(validateWsEvent({
        type: 'direct_message',
        targetUserId: uuid(1),
        text: 'hello',
        clientMsgId: 'weak-id'
    }).ok, false);
});

test('atomic insert creates once and replay returns the canonical persisted row', async () => {
    const row = {
        id: uuid(5),
        conversation_id: uuid(3),
        text: 'hello',
        msg_type: 'direct',
        created_at: '2026-09-24T12:00:00.000Z'
    };
    const createdPool = { query: async (sql) => ({ rows: sql.includes('INSERT INTO messages') ? [row] : [] }) };
    const created = await persistDirectMessage({
        pool: createdPool, conversationId: uuid(3), senderId: uuid(1),
        clientMsgId: uuid(2), text: 'hello', messageId: uuid(5)
    });
    assert.equal(created.kind, 'created');

    const calls = [];
    const replayPool = {
        query: async (sql) => {
            calls.push(sql);
            return { rows: sql.includes('INSERT INTO messages') ? [] : [row] };
        }
    };
    const replayed = await persistDirectMessage({
        pool: replayPool, conversationId: uuid(3), senderId: uuid(1),
        clientMsgId: uuid(2), text: 'hello', messageId: uuid(6)
    });
    assert.equal(replayed.kind, 'replayed');
    assert.match(calls[0], /ON CONFLICT \(sender_id, client_msg_id\).*DO NOTHING/s);
    const replayAck = buildDirectMessageAck({ clientMsgId: uuid(2), result: replayed });
    assert.equal(replayAck.status, 'persisted');
    assert.equal(replayAck.idempotency, 'replayed');
});

test('concurrent same-id persistence produces one created result and one replay', async () => {
    const canonical = {
        id: uuid(5), conversation_id: uuid(3), text: 'hello',
        msg_type: 'direct', created_at: '2026-09-24T12:00:00.000Z'
    };
    let inserted = false;
    const pool = {
        query: async (sql) => {
            if (sql.includes('INSERT INTO messages')) {
                if (inserted) return { rows: [] };
                inserted = true;
                return { rows: [canonical] };
            }
            return { rows: [canonical] };
        }
    };
    const input = {
        pool, conversationId: uuid(3), senderId: uuid(1),
        clientMsgId: uuid(2), text: 'hello', messageId: uuid(5)
    };
    const results = await Promise.all([
        persistDirectMessage(input),
        persistDirectMessage({ ...input, messageId: uuid(6) })
    ]);
    assert.deepEqual(results.map((result) => result.kind).sort(), ['created', 'replayed']);
    assert.equal(results[0].row.id, results[1].row.id);
});

test('conversation resolution serializes a user pair before selecting or creating', async () => {
    const statements = [];
    const client = {
        query: async (sql) => {
            statements.push(sql);
            if (sql.includes('SELECT id FROM conversations')) return { rows: [] };
            if (sql.includes('INSERT INTO conversations')) return { rows: [{ id: uuid(3) }] };
            return { rows: [] };
        },
        release: () => statements.push('RELEASE')
    };
    const resolved = await resolveDirectConversation({
        pool: { connect: async () => client },
        senderId: uuid(1),
        targetUserId: uuid(2),
        conversationId: uuid(3)
    });
    assert.equal(resolved, uuid(3));
    assert.match(statements[1], /pg_advisory_xact_lock/);
    assert.equal(statements.at(-2), 'COMMIT');
    assert.equal(statements.at(-1), 'RELEASE');
});

test('same client id with changed immutable payload is a terminal conflict', async () => {
    const pool = {
        query: async (sql) => ({ rows: sql.includes('INSERT INTO messages') ? [] : [{
            id: uuid(5), conversation_id: uuid(3), text: 'original',
            msg_type: 'direct', created_at: '2026-09-24T12:00:00.000Z'
        }] })
    };
    const result = await persistDirectMessage({
        pool, conversationId: uuid(3), senderId: uuid(1),
        clientMsgId: uuid(2), text: 'changed', messageId: uuid(6)
    });
    assert.equal(result.kind, 'conflict');
    assert.deepEqual(buildDirectMessageFailure({
        clientMsgId: uuid(2), errorCode: 'MESSAGE_ID_CONFLICT', retryable: false
    }), {
        type: 'direct_message_ack',
        protocolVersion: 1,
        clientMsgId: uuid(2),
        status: 'failed',
        errorCode: 'MESSAGE_ID_CONFLICT',
        retryable: false
    });
});

test('runtime fans out canonical direct events and history has a stable tie-breaker', () => {
    const indexSource = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    const historySource = fs.readFileSync(path.join(__dirname, '..', 'routes', 'friends.js'), 'utf8');
    assert.match(indexSource, /for \(const \[clientId, cData\] of activeClients\)/);
    assert.match(indexSource, /serverMessageId: persistResult\.row\.id/);
    assert.match(indexSource, /if \(persistResult\.kind === 'replayed'\) break/);
    assert.doesNotMatch(indexSource.slice(indexSource.indexOf("case 'typing':"), indexSource.indexOf("case 'leaveQueue':")), /\[DEBUG\]/);
    assert.match(historySource, /ORDER BY m\.created_at ASC, m\.id ASC/);
    assert.match(historySource, /serverMessageId: msg\.id/);
});
