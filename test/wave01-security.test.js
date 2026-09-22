const test = require('node:test');
const assert = require('node:assert/strict');
const {
    CHAT_MESSAGE_MAX_LENGTH,
    WS_MAX_PAYLOAD_BYTES,
    isAllowedWebSocketOrigin,
    validateWsEvent
} = require('../utils/wave01Security');

const UUID = '11111111-1111-4111-8111-111111111111';

test('hello_ack requires an authenticated bounded payload', () => {
    assert.equal(validateWsEvent({ type: 'hello_ack', deviceId: 'device-1', token: 'a'.repeat(64), platform: 'web', lang: 'tr' }).ok, true);
    assert.deepEqual(validateWsEvent({ type: 'hello_ack', deviceId: 'device-1', platform: 'web' }), { ok: false, code: 'INVALID_INPUT' });
});

test('unknown and extra event fields are rejected', () => {
    assert.equal(validateWsEvent({ type: 'not_real' }).code, 'UNKNOWN_EVENT');
    assert.equal(validateWsEvent({ type: 'joinQueue', admin: true }).code, 'UNEXPECTED_FIELD');
});

test('chat text is accepted at the limit and rejected above it', () => {
    assert.equal(validateWsEvent({ type: 'message', roomId: UUID, text: 'a'.repeat(CHAT_MESSAGE_MAX_LENGTH) }).ok, true);
    assert.equal(validateWsEvent({ type: 'message', roomId: UUID, text: 'a'.repeat(CHAT_MESSAGE_MAX_LENGTH + 1) }).ok, false);
});

test('authenticated events validate UUIDs and report context', () => {
    assert.equal(validateWsEvent({ type: 'fetch_image', mediaId: UUID }).ok, true);
    assert.equal(validateWsEvent({ type: 'fetch_image', mediaId: 'not-an-id' }).ok, false);
    assert.equal(validateWsEvent({ type: 'report', reason: 'Spam' }).ok, false);
    assert.equal(validateWsEvent({ type: 'report', reason: 'Spam', targetUserId: UUID }).ok, true);
});

test('image envelope stays below the websocket transport ceiling', () => {
    const twoMbBase64Chars = Math.ceil((2 * 1024 * 1024) / 3) * 4;
    assert.ok(twoMbBase64Chars < WS_MAX_PAYLOAD_BYTES);
});

test('websocket origin policy rejects missing and foreign origins', () => {
    const allowed = new Set(['https://talkx.chat', 'https://localhost', 'capacitor://localhost']);
    assert.equal(isAllowedWebSocketOrigin('https://talkx.chat', allowed), true);
    assert.equal(isAllowedWebSocketOrigin('https://localhost', allowed), true);
    assert.equal(isAllowedWebSocketOrigin('capacitor://localhost', allowed), true);
    assert.equal(isAllowedWebSocketOrigin(undefined, allowed), false);
    assert.equal(isAllowedWebSocketOrigin('https://evil.example', allowed), false);
});
