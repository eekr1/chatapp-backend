const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { normalizeCountryCode, evaluateCountryCandidate, displayCountry } = require('../utils/countryPolicy');
const { planCountryBackfill } = require('../utils/countryBackfill');
const { validateRegistry, validateStoreCoverage, registry, POLICY_VERSION } = require('../utils/dataPolicyRegistry');
const { validatePrivacyClaims } = require('../utils/privacyClaims');
const { createRetentionRunner } = require('../utils/retentionRunner');
const { buildSubjectRef, canRejectDeletion, executeAccountDeletion } = require('../utils/accountDeletion');
const { onUserRuntimeTermination, requestUserRuntimeTermination } = require('../utils/userRuntimeTermination');

test('country policy is strict, ISO based and privacy-safe', () => {
    assert.equal(normalizeCountryCode('Türkiye'), 'TR');
    assert.equal(normalizeCountryCode(' turkey '), 'TR');
    assert.equal(normalizeCountryCode('Turkiyee'), null);
    assert.equal(evaluateCountryCandidate({ country: 'TR', source: 'private', observedAt: new Date() }).status, 'unavailable');
    assert.equal(evaluateCountryCandidate({ country: 'TR', source: 'registration_ip', observedAt: '2020-01-01', now: new Date('2026-01-01') }).status, 'stale');
    const eligible = evaluateCountryCandidate({ country: 'TR', source: 'registration_ip', observedAt: '2026-01-01', now: new Date('2026-01-02') });
    assert.deepEqual(eligible, { countryCode: 'TR', status: 'eligible', confidence: 'policy_verified', policyVersion: 'match-country-v1' });
    assert.ok(displayCountry('TR', 'tr'));
});

test('country backfill detects conflicts and never overwrites a newer canonical record', () => {
    const now = new Date('2026-09-24T00:00:00Z');
    const plan = planCountryBackfill({
        now,
        candidates: [
            { user_id: 'u1', location_country: 'Turkey', location_source: 'registration_ip', location_resolved_at: '2026-09-20' },
            { user_id: 'u1', location_country: 'Germany', location_source: 'registration_ip', location_resolved_at: '2026-09-21' },
            { user_id: 'u2', location_country: 'TR', location_source: 'registration_ip', location_resolved_at: '2026-09-20' },
            { user_id: 'u3', location_country: 'unresolved', location_source: 'unresolved', location_resolved_at: '2026-09-22' }
        ],
        existing: new Map([
            ['u2', { updated_at: '2026-09-23', status: 'eligible' }],
            ['u3', { updated_at: '2026-09-20', status: 'eligible' }]
        ])
    });
    assert.equal(plan.writes[0].status, 'disputed');
    assert.equal(plan.counts.disputed, 1);
    assert.equal(plan.counts.skippedNewer, 2);
});

test('registry is structurally complete while human/legal release gates remain fail-closed', () => {
    const structural = validateRegistry();
    assert.equal(structural.ok, true, structural.errors.join(','));
    assert.equal(structural.policyVersion, POLICY_VERSION);
    assert.ok(structural.classCount >= 18);
    assert.equal(validateRegistry({ release: true }).ok, false);
    assert.equal(validatePrivacyClaims().ok, true);
    assert.equal(validatePrivacyClaims({ release: true }).ok, false);
    const schemaStores = [
        'users','sessions','profiles','friendships','users_anon','conversations','reports','bans','ephemeral_media','messages',
        'push_devices','push_delivery_logs','support_reports','support_report_media','blocks','app_settings','notification_schedules',
        'legal_acceptances','account_deletion_requests','account_deletion_steps','erasure_journal','admin_action_audit',
        'http_request_events','http_request_metrics_minute','behavior_events','connection_leases','user_match_country'
    ];
    assert.deepEqual(validateStoreCoverage(schemaStores), { ok: true, missing: [] });
});

test('retention defaults to deterministic dry-run and execute requires explicit approval plus completed policy', async () => {
    const calls = [];
    const client = { query: async (sql) => { calls.push(sql); return /try_advisory/.test(sql) ? { rows: [{ locked: true }] } : { rows: [] }; }, release() {} };
    const runner = createRetentionRunner({ pool: { connect: async () => client }, registry, now: () => new Date('2026-09-24T00:00:00Z') });
    const first = await runner.run({ policyVersion: POLICY_VERSION });
    const second = await runner.run({ policyVersion: POLICY_VERSION });
    assert.equal(first.mode, 'dry_run');
    assert.equal(first.cutoff, second.cutoff);
    await assert.rejects(runner.run({ mode: 'execute', policyVersion: POLICY_VERSION }), (error) => error.code === 'RETENTION_EXECUTE_NOT_APPROVED');
    await assert.rejects(runner.run({ mode: 'execute', executeApproved: true, policyVersion: POLICY_VERSION }), (error) => error.code === 'RETENTION_POLICY_INCOMPLETE');
    assert.ok(calls.some((sql) => /advisory_unlock/.test(sql)));
});

test('deletion transitions, HMAC subject reference and runtime broadcast are deterministic', async () => {
    assert.equal(canRejectDeletion('requested'), true);
    assert.equal(canRejectDeletion('processing'), false);
    const a = buildSubjectRef({ userId: 'user-1', hmacKey: 'x'.repeat(32) });
    const b = buildSubjectRef({ userId: 'user-1', hmacKey: 'x'.repeat(32) });
    assert.equal(a, b);
    assert.doesNotMatch(a, /user-1/);
    const seen = [];
    const off = onUserRuntimeTermination(async (event) => seen.push(event));
    const ack = await requestUserRuntimeTermination({ userId: 'user-1', requestId: 'request-1' });
    off();
    assert.equal(ack.failed, 0);
    assert.equal(seen[0].requestId, 'request-1');
});

test('deletion worker records per-class evidence, minimum receipt and idempotent journal', async () => {
    const calls = [];
    const client = {
        query: async (sql, params) => {
            calls.push([sql, params]);
            if (/SELECT id, user_id, status/.test(sql)) return { rows: [{ id: 'r1', user_id: 'u1', status: 'requested', policy_version: POLICY_VERSION, receipt: null }], rowCount: 1 };
            if (/AS remaining/.test(sql)) return { rows: [{ remaining: 0 }], rowCount: 1 };
            return { rows: [], rowCount: /^\s*(DELETE|UPDATE)/.test(sql) ? 1 : 0 };
        },
        release() {}
    };
    const result = await executeAccountDeletion({ pool: { connect: async () => client }, requestId: 'r1', actorAdmin: 'admin', hmacKey: 'k'.repeat(32) });
    assert.equal(result.receipt.status, 'completed');
    assert.ok(result.steps.some((step) => step.stepKey === 'runtime_leases'));
    assert.ok(result.steps.some((step) => step.stepKey === 'support'));
    assert.ok(result.steps.some((step) => step.stepKey === 'orphan_verification'));
    assert.ok(calls.some(([sql]) => /INSERT INTO erasure_journal/.test(sql)));
    assert.ok(calls.some(([sql]) => /DELETION_COMPLETE/.test(sql)));
});

test('migration 003 and API sources carry Wave 06 safeguards without Wave 07 scope', () => {
    const root = path.join(__dirname, '..');
    const db = fs.readFileSync(path.join(root, 'db.js'), 'utf8');
    const profile = fs.readFileSync(path.join(root, 'routes', 'profile.js'), 'utf8');
    const support = fs.readFileSync(path.join(root, 'routes', 'support.js'), 'utf8');
    assert.match(db, /version: '003'/);
    assert.match(db, /CREATE TABLE IF NOT EXISTS user_match_country/);
    assert.match(db, /CREATE TABLE IF NOT EXISTS account_deletion_steps/);
    assert.match(db, /CREATE TABLE IF NOT EXISTS erasure_journal/);
    assert.match(profile, /\/me\/match-country/);
    assert.match(profile, /requestUserRuntimeTermination/);
    assert.match(support, /ON CONFLICT \(submission_scope_hash, submission_id\)/);
    assert.doesNotMatch(profile, /preferredMatchScope|effectiveMatchScope|country_fallback/);
});
