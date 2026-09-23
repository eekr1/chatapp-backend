const test = require('node:test');
const assert = require('node:assert/strict');

process.env.DATABASE_URL ||= 'postgres://user:pass@localhost:5432/test';

const { buildErrorEnvelope, requestContext } = require('../utils/contracts');
const { createLogEntry, sanitizeFields } = require('../utils/logger');
const { BoundedRateLimiter, actorKeys } = require('../utils/abuseProtection');
const {
    createSession,
    normalizeDeviceId,
    parseBearerToken,
    revokeAllForUser
} = require('../utils/sessionService');
const { ConnectionRegistry, PHASES, normalizeClientContext, safeSend } = require('../utils/socketSecurity');
const { capabilityFor, parseBasicAuth, safeEqual } = require('../utils/adminSecurity');

test('canonical API error keeps legacy aliases and retry metadata', () => {
    const body = buildErrorEnvelope({
        errorCode: 'RATE_LIMITED', message: 'wait', requestId: 'req-1', retryable: true, retryAfterMs: 1250
    });
    assert.equal(body.schemaVersion, '1');
    assert.equal(body.errorCode, 'RATE_LIMITED');
    assert.equal(body.code, 'RATE_LIMITED');
    assert.equal(body.error, 'wait');
    assert.equal(body.requestId, 'req-1');
    assert.equal(body.retryAfterMs, 1250);
    assert.match(body.serverTime, /^\d{4}-\d{2}-\d{2}T/);
});

test('request context accepts safe IDs and rejects uncontrolled values', () => {
    const headers = {};
    const req = { get: () => 'safe-request:1' };
    const res = { setHeader: (key, value) => { headers[key] = value; } };
    let called = false;
    requestContext(req, res, () => { called = true; });
    assert.equal(req.requestId, 'safe-request:1');
    assert.equal(headers['X-Request-ID'], 'safe-request:1');
    assert.equal(headers['X-TalkX-Contract-Version'], '1');
    assert.equal(called, true);
});

test('structured logger drops secrets, content, full IP and arbitrary bodies', () => {
    const clean = sanitizeFields({
        requestId: 'r1', actor: 'user-123', password: 'secret', token: 'raw',
        authorization: 'Bearer raw', message: 'private chat', ip: '203.0.113.2', body: { password: 'secret' }
    });
    assert.equal(clean.requestId, 'r1');
    assert.match(clean.actor, /^[a-f0-9]{16}$/);
    assert.equal(clean.password, undefined);
    assert.equal(clean.token, undefined);
    assert.equal(clean.message, undefined);
    assert.equal(clean.ip, undefined);
    assert.equal(clean.body, undefined);
    const entry = createLogEntry('warn', 'auth', 'denied', clean);
    assert.equal(entry.component, 'auth');
});

test('bounded limiter returns exact retry and evicts expired/flood keys', () => {
    let now = 1000;
    const limiter = new BoundedRateLimiter({ windowMs: 1000, max: 2, maxKeys: 2, now: () => now });
    assert.equal(limiter.consume('a').allowed, true);
    assert.equal(limiter.consume('a').allowed, true);
    const denied = limiter.consume('a');
    assert.equal(denied.allowed, false);
    assert.equal(denied.retryAfterMs, 1000);
    limiter.consume('b');
    limiter.consume('c');
    assert.equal(limiter.buckets.size, 2);
    now = 2001;
    assert.equal(limiter.consume('a').allowed, true);
    assert.equal(limiter.buckets.size, 1);
});

test('actor keys separate NAT users by user/device without exposing IP', () => {
    const req = { socket: { remoteAddress: '203.0.113.5' } };
    const first = actorKeys({ req, userId: 'user-a', deviceId: 'device-a' });
    const second = actorKeys({ req, userId: 'user-b', deviceId: 'device-b' });
    assert.equal(first[0], second[0]);
    assert.notEqual(first[1], second[1]);
    assert.ok(first.every((key) => !key.includes('203.0.113.5')));
});

test('session token parsing and device normalization are strict', () => {
    assert.equal(parseBearerToken('Bearer abc.def'), 'abc.def');
    assert.equal(parseBearerToken('Basic abc'), null);
    assert.equal(parseBearerToken('Bearer two tokens'), null);
    assert.equal(normalizeDeviceId('  phone-1  '), 'phone-1');
    assert.equal(normalizeDeviceId(''), 'unknown');
});

test('same user/device login replaces the session in one transaction', async () => {
    const calls = [];
    const db = { query: async (sql, params) => { calls.push([sql, params]); return { rows: [] }; } };
    const created = await createSession({ userId: 'user-1', deviceId: 'device-1' }, db);
    assert.equal(calls[0][0], 'BEGIN');
    assert.match(calls[1][0], /DELETE FROM sessions WHERE user_id/);
    assert.match(calls[2][0], /INSERT INTO sessions/);
    assert.equal(calls[3][0], 'COMMIT');
    assert.equal(calls[1][1][1], 'device-1');
    assert.ok(created.token.length >= 32);
    assert.notEqual(created.token, created.tokenHash);
});

test('all-device revoke reports every removed session to listeners', async () => {
    const db = { query: async () => ({ rows: [
        { token_hash: 'hash-1', user_id: 'u1', device_id: 'd1' },
        { token_hash: 'hash-2', user_id: 'u1', device_id: 'd2' }
    ] }) };
    const rows = await revokeAllForUser('u1', 'password_changed', db);
    assert.equal(rows.length, 2);
});

test('socket registry enforces one immutable handshake and session ownership', () => {
    const registry = new ConnectionRegistry();
    const ws = { readyState: 1, bufferedAmount: 0, send() {}, close() {} };
    const entry = registry.connect(ws, 'connection-1');
    assert.equal(entry.phase, PHASES.CONNECTED);
    assert.equal(registry.beginAuthentication('connection-1'), true);
    assert.equal(registry.beginAuthentication('connection-1'), false);
    assert.equal(registry.authenticate('connection-1', { sessionId: 'session-1', userId: 'user-1' }), true);
    assert.equal(registry.authenticate('connection-1', { sessionId: 'session-2', userId: 'user-2' }), false);
    assert.equal(registry.isAuthenticated('connection-1'), true);
    assert.equal(registry.get('connection-1').userId, 'user-1');
    assert.deepEqual([...registry.bySession.get('session-1')], ['connection-1']);
});

test('session revoke closes every socket owned by that session', () => {
    const registry = new ConnectionRegistry();
    const closes = [];
    const createWs = (name) => ({
        readyState: 1, bufferedAmount: 0, send() {}, close: (code, reason) => closes.push([name, code, reason])
    });
    for (const name of ['a', 'b']) {
        registry.connect(createWs(name), name);
        registry.beginAuthentication(name);
        registry.authenticate(name, { sessionId: 'session-1', userId: 'user-1' });
    }
    registry.closeSessions([{ token_hash: 'session-1' }], 'password_changed');
    assert.deepEqual(closes, [
        ['a', 1008, 'password_changed'],
        ['b', 1008, 'password_changed']
    ]);
});

test('safe socket send adds contract metadata and closes slow consumers', () => {
    let payload;
    let closeCode;
    const ws = { readyState: 1, bufferedAmount: 0, send: (value) => { payload = JSON.parse(value); }, close: (code) => { closeCode = code; } };
    assert.equal(safeSend(ws, { type: 'welcome' }).ok, true);
    assert.equal(payload.schemaVersion, '1');
    assert.match(payload.eventId, /^[0-9a-f-]{36}$/);
    ws.bufferedAmount = 600 * 1024;
    assert.equal(safeSend(ws, { type: 'message' }).reason, 'backpressure');
    assert.equal(closeCode, 1013);
});

test('client socket context is allowlisted and bounded', () => {
    const context = normalizeClientContext({
        deviceId: ' d1 ', platform: 'ios', lang: 'de', appVersion: '1.2.3',
        capabilities: ['a', 42, 'b']
    });
    assert.deepEqual(context, { deviceId: 'd1', platform: 'web', locale: 'en', release: '1.2.3', capabilities: ['a', 'b'] });
});

test('admin auth parsing is strict and routes map to server capabilities', () => {
    const header = `Basic ${Buffer.from('admin:secret').toString('base64')}`;
    assert.deepEqual(parseBasicAuth(header), { username: 'admin', password: 'secret' });
    assert.equal(safeEqual('secret', 'secret'), true);
    assert.equal(safeEqual('secret', 'wrong'), false);
    assert.equal(capabilityFor('POST', '/deletion-requests/id/approve-delete'), 'account/deletion');
    assert.equal(capabilityFor('PUT', '/legal'), 'content/publish');
    assert.equal(capabilityFor('GET', '/profile-details/id'), 'sensitive-read');
    assert.equal(capabilityFor('POST', '/ban'), 'moderation/action');
});
