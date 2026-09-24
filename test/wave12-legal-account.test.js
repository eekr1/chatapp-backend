const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { DEFAULT_LEGAL_CONTENT } = require('../utils/legalContent');
const {
    buildLegalRelease,
    buildRequirementFingerprint,
    calculateLegalStatus,
    acceptLegalRequirement
} = require('../utils/legalAcceptance');

const clone = (value) => JSON.parse(JSON.stringify(value));

test('Wave 12 legal release identity is deterministic and content bound', () => {
    const first = buildLegalRelease({ item: clone(DEFAULT_LEGAL_CONTENT), updatedAt: '2026-09-25T00:00:00Z' });
    const replay = buildLegalRelease({ item: clone(DEFAULT_LEGAL_CONTENT), updatedAt: '2026-09-26T00:00:00Z' });
    const changedContent = clone(DEFAULT_LEGAL_CONTENT);
    changedContent.documents.terms.en.content += ' Changed.';
    const changed = buildLegalRelease({ item: changedContent });
    assert.equal(first.releaseId, replay.releaseId);
    assert.equal(first.revision, replay.revision);
    assert.notEqual(first.releaseId, changed.releaseId);
    assert.equal(first.format, 'plain_text');
});

test('Wave 12 requirement identity follows Terms and Privacy versions only', () => {
    assert.equal(
        buildRequirementFingerprint({ terms: 'v2', privacy: 'v3' }),
        buildRequirementFingerprint({ privacy: 'v3', terms: 'v2' })
    );
    assert.notEqual(
        buildRequirementFingerprint({ terms: 'v2', privacy: 'v3' }),
        buildRequirementFingerprint({ terms: 'v2', privacy: 'v4' })
    );
});

test('Wave 12 legal status never treats missing or mismatched acceptance as accepted', async () => {
    const makeDb = (acceptance) => ({
        query: async (sql) => {
            if (/FROM app_settings/.test(sql)) return { rows: [{ value: clone(DEFAULT_LEGAL_CONTENT), updated_at: '2026-09-25T00:00:00Z' }] };
            if (/FROM legal_acceptances/.test(sql)) return { rows: acceptance ? [acceptance] : [] };
            throw new Error(`Unexpected query: ${sql}`);
        }
    });
    const missing = await calculateLegalStatus(makeDb(null), 'user-1');
    assert.equal(missing.requiresReaccept, true);
    assert.equal(missing.reason, 'missing_acceptance');
    const current = await calculateLegalStatus(makeDb({ terms_version: 'v1', privacy_version: 'v1', accepted_at: 'now' }), 'user-1');
    assert.equal(current.requiresReaccept, false);
    assert.equal(current.reason, null);
    const stale = await calculateLegalStatus(makeDb({ terms_version: 'v0', privacy_version: 'v1', accepted_at: 'then' }), 'user-1');
    assert.equal(stale.requiresReaccept, true);
    assert.equal(stale.reason, 'terms_changed');
});

test('Wave 12 accept locks the current release and returns the persisted timestamp', async () => {
    const calls = [];
    const release = buildLegalRelease({ item: clone(DEFAULT_LEGAL_CONTENT), updatedAt: '2026-09-25T00:00:00Z' });
    const client = {
        query: async (sql) => {
            calls.push(sql);
            if (/FROM app_settings/.test(sql)) return { rows: [{ value: clone(DEFAULT_LEGAL_CONTENT), updated_at: '2026-09-25T00:00:00Z' }] };
            if (/WHERE user_id=\$1 AND command_id=\$2/.test(sql)) return { rows: [] };
            if (/INSERT INTO legal_acceptances/.test(sql)) return { rows: [{
                terms_version: 'v1', privacy_version: 'v1', accepted_at: '2026-09-25T01:00:00Z',
                release_id: release.releaseId, release_revision: release.revision,
                requirement_fingerprint: buildRequirementFingerprint(release.required), command_id: 'command-123', locale: 'tr'
            }] };
            return { rows: [] };
        },
        release() {}
    };
    const result = await acceptLegalRequirement({
        pool: { connect: async () => client }, userId: 'user-1', expectedReleaseId: release.releaseId,
        termsVersion: 'v1', privacyVersion: 'v1', commandId: 'command-123', locale: 'tr'
    });
    assert.equal(result.accepted.accepted_at, '2026-09-25T01:00:00Z');
    assert.equal(result.replayed, false);
    assert.ok(calls.some((sql) => /FOR SHARE/.test(sql)));
    assert.ok(calls.some((sql) => /ON CONFLICT \(user_id,requirement_fingerprint\)/.test(sql)));
});

test('Wave 12 sources keep reduced Sale scope and idempotent account commands', () => {
    const root = path.join(__dirname, '..');
    const db = fs.readFileSync(path.join(root, 'db.js'), 'utf8');
    const profile = fs.readFileSync(path.join(root, 'routes', 'profile.js'), 'utf8');
    const support = fs.readFileSync(path.join(root, 'routes', 'support.js'), 'utf8');
    const index = fs.readFileSync(path.join(root, 'index.js'), 'utf8');
    assert.match(db, /version: '006'/);
    assert.match(db, /idx_legal_acceptance_requirement/);
    assert.match(profile, /Idempotency-Key/);
    assert.match(support, /ON CONFLICT \(submission_scope_hash, submission_id\)/);
    assert.match(index, /LEGAL_STATUS_UNAVAILABLE/);
    assert.doesNotMatch(db, /legal_drafts|legal_publications/);
});
