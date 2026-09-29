const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
    buildAudienceSummary,
    normalizeNoticeContentByLocale,
    normalizeNoticeTarget
} = require('../utils/adminNotificationContract');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('admin notification content requires complete bounded TR and EN variants', () => {
    assert.deepEqual(normalizeNoticeContentByLocale({
        tr: { title: ' Duyuru ', body: ' Merhaba ' },
        en: { title: ' Notice ', body: ' Hello ' }
    }), {
        tr: { title: 'Duyuru', body: 'Merhaba' },
        en: { title: 'Notice', body: 'Hello' }
    });
    assert.equal(normalizeNoticeContentByLocale({ tr: { title: 'Eksik', body: 'EN yok' } }), null);
    assert.equal(normalizeNoticeContentByLocale({
        tr: { title: 'x'.repeat(121), body: 'Metin' },
        en: { title: 'Notice', body: 'Body' }
    }), null);
});

test('admin notification targeting is allowlisted and audience counts deduplicate users', () => {
    assert.equal(normalizeNoticeTarget('online'), 'online');
    assert.equal(normalizeNoticeTarget('country'), null);
    assert.deepEqual(buildAudienceSummary({
        target: 'all',
        online: [
            { userId: 'u1', locale: 'tr' },
            { userId: 'u1', locale: 'tr' },
            { userId: 'u2', locale: 'en', fallback: true }
        ],
        push: [
            { userId: 'u1', locale: 'tr' },
            { userId: 'u3', locale: 'en' }
        ]
    }), {
        target: 'all',
        recipientCount: 3,
        wsConnections: 3,
        wsUsers: 2,
        pushDevices: 2,
        pushUsers: 2,
        localeDeliveries: { tr: 3, en: 2, fallback: 1 }
    });
});

test('localized schedules migrate safely and every send path uses the shared contract', () => {
    const db = read('db.js');
    const admin = read('admin.js');
    const index = read('index.js');
    assert.match(db, /version:\s*'009'/);
    assert.match(db, /requires_translation = TRUE[\s\S]*is_active = FALSE/);
    assert.match(admin, /router\.get\('\/notification-audience'/);
    assert.match(admin, /content_by_locale/);
    assert.match(index, /WHERE is_active = TRUE AND requires_translation = FALSE/);
    assert.match(index, /adminRoutes\.getSystemNoticeAudience/);
    assert.match(index, /renderLocale: locale/);
    assert.doesNotMatch(index, /sendSystemNotice = async \(\{ title, body/);
});
