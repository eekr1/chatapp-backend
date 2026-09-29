const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { DEFAULT_LEGAL_CONTENT } = require('../utils/legalContent');
const {
    extractLegalSection,
    applyLegalSection,
    hashLegalContent,
    buildLegalDiff,
    evaluateLegalPublication
} = require('../utils/legalPublishing');

const clone = (value) => JSON.parse(JSON.stringify(value));

test('legal drafts isolate one document from the published aggregate', () => {
    const live = clone(DEFAULT_LEGAL_CONTENT);
    const privacy = extractLegalSection(live, 'privacy');
    privacy.document.tr.content += '\nYeni açıklama.';
    const next = applyLegalSection(live, 'privacy', privacy);
    assert.notEqual(next.documents.privacy.tr.content, live.documents.privacy.tr.content);
    assert.deepEqual(next.documents.terms, live.documents.terms);
    assert.deepEqual(next.footer, live.footer);
});

test('legal diff is field based and content hashes are deterministic', () => {
    const live = clone(DEFAULT_LEGAL_CONTENT);
    const section = extractLegalSection(live, 'footer');
    section.footer.tr.tagline = 'Yeni slogan';
    const next = applyLegalSection(live, 'footer', section);
    const diff = buildLegalDiff(live, next, 'footer');
    assert.equal(diff.changed, true);
    assert.equal(diff.changedFieldCount, 1);
    assert.equal(diff.fields[0].field, 'footer.tr.tagline');
    assert.equal(hashLegalContent(live), hashLegalContent(clone(live)));
    assert.notEqual(hashLegalContent(live), hashLegalContent(next));
});

test('material Terms or Privacy publication fails closed without a version bump', () => {
    const live = clone(DEFAULT_LEGAL_CONTENT);
    const section = extractLegalSection(live, 'terms');
    section.document.tr.content = 'Topluluk kurallarina ve gecerli mevzuata uygun davraniş zorunludur.';
    section.document.en.content = 'Compliance with community rules and applicable law is required. Material clause.';
    assert.throws(
        () => evaluateLegalPublication({ liveContent: live, draftSection: section, documentKey: 'terms', changeClass: 'material' }),
        /surumu artirilmalidir/
    );
    section.version = 'v2';
    const result = evaluateLegalPublication({ liveContent: live, draftSection: section, documentKey: 'terms', changeClass: 'material' });
    assert.equal(result.versionChanged, true);
    assert.equal(result.requiresReaccept, true);
});

test('publication blocks placeholder content while draft composition remains possible', () => {
    const live = clone(DEFAULT_LEGAL_CONTENT);
    const section = extractLegalSection(live, 'privacy');
    assert.throws(
        () => evaluateLegalPublication({ liveContent: live, draftSection: section, documentKey: 'privacy', changeClass: 'clarification' }),
        /placeholder/
    );
});

test('clarification can preserve acceptance while Child Safety never changes requirement versions', () => {
    const live = clone(DEFAULT_LEGAL_CONTENT);
    const privacy = extractLegalSection(live, 'privacy');
    privacy.document.tr.content = 'Kisisel veriler hizmet, guvenlik ve yasal yukumlulukler icin islenir.';
    privacy.document.en.content = 'Personal data is processed for service, security and legal compliance.';
    const privacyResult = evaluateLegalPublication({ liveContent: live, draftSection: privacy, documentKey: 'privacy', changeClass: 'clarification' });
    assert.equal(privacyResult.versionChanged, false);
    assert.equal(privacyResult.requiresReaccept, false);
    const safety = extractLegalSection(live, 'childSafety');
    safety.document.tr.content = 'TalkX, cocuk istismari ve suistimali iceriklerini kesin olarak yasaklar.';
    safety.document.en.content = 'TalkX strictly prohibits child abuse and exploitation content. Clarified.';
    const safetyResult = evaluateLegalPublication({ liveContent: live, draftSection: safety, documentKey: 'childSafety', changeClass: 'clarification' });
    assert.equal(safetyResult.requiresReaccept, false);
    assert.deepEqual(safetyResult.nextContent.versions, live.versions);
});

test('admin legal publishing contract separates draft, preview, publish and rollback', () => {
    const root = path.join(__dirname, '..');
    const admin = fs.readFileSync(path.join(root, 'admin.js'), 'utf8');
    const ui = fs.readFileSync(path.join(root, 'admin.html'), 'utf8');
    const db = fs.readFileSync(path.join(root, 'db.js'), 'utf8');
    assert.match(db, /version: '010'/);
    assert.match(db, /CREATE TABLE IF NOT EXISTS legal_content_workspaces/);
    assert.match(db, /CREATE TABLE IF NOT EXISTS legal_content_publications/);
    assert.match(admin, /router\.put\('\/legal-drafts\/:documentKey'/);
    assert.match(admin, /router\.post\('\/legal-publications\/preview'/);
    assert.match(admin, /router\.get\('\/legal-publications\/:id'/);
    assert.match(admin, /confirmPublish !== true/);
    assert.match(admin, /LEGAL_REVISION_CONFLICT/);
    assert.match(admin, /LEGAL_ROLLBACK_PUBLISH/);
    assert.match(ui, /Yasal İçerik Yayın Merkezi/);
    assert.match(ui, /Farkı ve etkiyi incele/);
    assert.match(ui, /Taslağa al/);
    assert.match(ui, /Kanıtı gör/);
});
