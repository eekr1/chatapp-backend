const test = require('node:test');
const assert = require('node:assert/strict');
const { filterAnonMessage, isEnabled } = require('../utils/textFilter');

test('isEnabled reads TEXT_FILTER_ENABLED', () => {
    assert.equal(isEnabled({}), true);
    assert.equal(isEnabled({ TEXT_FILTER_ENABLED: 'true' }), true);
    assert.equal(isEnabled({ TEXT_FILTER_ENABLED: 'false' }), false);
    assert.equal(isEnabled({ TEXT_FILTER_ENABLED: 'FALSE' }), false);
});

test('masks URLs', () => {
    assert.ok(filterAnonMessage('visit https://example.com now').masked);
    assert.equal(filterAnonMessage('visit https://example.com now').reasons.includes('url'), true);
    assert.ok(filterAnonMessage('www.example.com').masked);
    assert.ok(filterAnonMessage('ornek.com.tr').masked);
    assert.ok(filterAnonMessage('site.xyz').masked);
    assert.ok(filterAnonMessage('t.me/kanal').masked);
    assert.ok(filterAnonMessage('wa.me/905551112233').masked);
    assert.ok(filterAnonMessage('discord.gg/abcd').masked);
});

test('masks e-mail addresses', () => {
    const res = filterAnonMessage('mail: test.user@example.com');
    assert.ok(res.masked);
    assert.ok(res.reasons.includes('email'));
    assert.equal(res.text.includes('test.user@example.com'), false);
});

test('masks phone numbers', () => {
    assert.ok(filterAnonMessage('0532 111 22 33').masked);
    assert.ok(filterAnonMessage('+905321112233').masked);
    assert.ok(filterAnonMessage('0532.111.22.33').masked);
    assert.ok(filterAnonMessage('0532-111-22-33').masked);
    const res = filterAnonMessage('numara 05551112233');
    assert.ok(res.reasons.includes('phone'));
});

test('masks platform + username, keeps the platform word', () => {
    const res = filterAnonMessage('instagram: john.doe');
    assert.ok(res.masked);
    assert.ok(res.reasons.includes('platform'));
    assert.equal(res.text.includes('john.doe'), false);
    assert.ok(res.text.includes('instagram'));
    assert.ok(filterAnonMessage('telegram @user123').masked);
    assert.ok(filterAnonMessage('snapchat: coolguy').masked);
    assert.ok(filterAnonMessage('discord: gamer_42').masked);
    assert.ok(filterAnonMessage('tiktok @dancer').masked);
    assert.ok(filterAnonMessage('ig: someone').masked);
    assert.ok(filterAnonMessage('tg: someone').masked);
});

test('masks Turkish slurs', () => {
    assert.ok(filterAnonMessage('sen orospu').masked);
    const res = filterAnonMessage('orospu');
    assert.ok(res.reasons.includes('slur'));
    assert.ok(filterAnonMessage('AMK').masked);
    assert.ok(filterAnonMessage('amk').masked);
    assert.ok(filterAnonMessage('SİKTİR').masked);
    assert.ok(filterAnonMessage('yarrak').masked);
});

test('masks English slurs', () => {
    assert.ok(filterAnonMessage('what the fuck').masked);
    assert.ok(filterAnonMessage('FUCK').masked);
    assert.ok(filterAnonMessage('you bitch').masked);
    assert.ok(filterAnonMessage('sh1t').masked);
    assert.ok(filterAnonMessage('f@ck').masked);
    const res = filterAnonMessage('fuck');
    assert.ok(res.reasons.includes('slur'));
});

test('keeps innocent words that contain slur-like substrings', () => {
    const innocent = [
        'amazon', 'Amazon', 'ambulans', 'sikke', 'classic', 'assist',
        'Scunthorpe', 'analysis', 'piano', 'ticket', 'basic', 'Dickens'
    ];
    for (const word of innocent) {
        const res = filterAnonMessage(word);
        assert.equal(res.masked, false, `expected no mask for: ${word}`);
        assert.equal(res.text, word);
    }
});

test('leaves normal chat untouched', () => {
    const res = filterAnonMessage('merhaba, nasilsin?');
    assert.equal(res.masked, false);
    assert.equal(res.text, 'merhaba, nasilsin?');
    assert.deepEqual(res.reasons, []);
});

test('handles empty and non-string input', () => {
    assert.deepEqual(filterAnonMessage(''), { text: '', masked: false, reasons: [] });
    assert.equal(filterAnonMessage(null).masked, false);
    assert.equal(filterAnonMessage(undefined).masked, false);
    assert.equal(filterAnonMessage(123).masked, false);
});
