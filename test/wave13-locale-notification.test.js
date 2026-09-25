const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const messagesEn = require('../i18n/messages.en');
const messagesTr = require('../i18n/messages.tr');
const {
    resolveDeliveryLocale,
    selectLocalizedPayload
} = require('../utils/notificationLocale');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const flatten = (value, prefix = '', result = {}) => {
    for (const [key, entry] of Object.entries(value || {})) {
        const next = prefix ? `${prefix}.${key}` : key;
        if (entry && typeof entry === 'object') flatten(entry, next, result);
        else result[next] = entry;
    }
    return result;
};
const placeholders = (value) => Array.from(String(value || '').matchAll(/\{([^}]+)\}/g))
    .map((match) => match[1])
    .sort();

test('Wave 13 backend TR and EN dictionaries keep key and placeholder parity', () => {
    const en = flatten(messagesEn);
    const tr = flatten(messagesTr);
    assert.deepEqual(Object.keys(tr).sort(), Object.keys(en).sort());
    for (const key of Object.keys(en)) {
        assert.deepEqual(placeholders(tr[key]), placeholders(en[key]), key);
    }
});

test('Wave 13 push locale prefers device, then profile, then explicit English fallback', () => {
    assert.deepEqual(resolveDeliveryLocale({ deviceLocale: 'tr', profileLocale: 'en' }), {
        locale: 'tr', source: 'device', fallbackReason: null
    });
    assert.deepEqual(resolveDeliveryLocale({ deviceLocale: 'de', profileLocale: 'tr' }), {
        locale: 'tr', source: 'profile', fallbackReason: null
    });
    assert.deepEqual(resolveDeliveryLocale({ deviceLocale: null, profileLocale: null }), {
        locale: 'en', source: 'fallback', fallbackReason: 'missing_or_unsupported'
    });
});

test('Wave 13 localized payload selection is atomic and records safe fallback metadata', () => {
    const variants = {
        en: { title: 'TalkX', body: 'Sent a photo', data: { type: 'direct_message' } },
        tr: { title: 'TalkX', body: 'Fotograf gonderdi', data: { type: 'direct_message' } }
    };
    const tr = selectLocalizedPayload(variants, { locale: 'tr', source: 'device' });
    assert.equal(tr.body, 'Fotograf gonderdi');
    assert.equal(tr.data.renderLocale, 'tr');
    assert.equal(tr.data.localeSource, 'device');
    assert.equal(tr.data.fallbackReason, undefined);

    const fallback = selectLocalizedPayload({ en: variants.en }, {
        locale: 'tr', source: 'fallback', fallbackReason: 'variant_not_available'
    });
    assert.equal(fallback.body, 'Sent a photo');
    assert.equal(fallback.data.renderLocale, 'en');
    assert.equal(fallback.data.fallbackReason, 'variant_not_available');
});

test('Wave 13 persists device locale and keeps localized push delivery bounded to current channels', () => {
    const db = read('db.js');
    const pushRoute = read('routes/push.js');
    const index = read('index.js');

    assert.match(db, /version:\s*'007'/);
    assert.match(db, /ADD COLUMN IF NOT EXISTS locale TEXT/);
    assert.match(pushRoute, /locale_updated_at/);
    assert.match(pushRoute, /locale_source/);
    assert.match(index, /payloadByLocale/);
    assert.match(index, /localeSummary/);
    assert.doesNotMatch(index, /system_message_campaigns/);
});
