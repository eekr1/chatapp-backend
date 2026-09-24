const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createSearchLifecycle } = require('../utils/searchLifecycle');
const {
    assertMatchScopeTopology,
    queueKeyFor,
    resolveCanonicalMatchScope
} = require('../utils/matchScope');
const { validateWsEvent } = require('../utils/wave01Security');

const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const country = (code) => ({
    requestedScope: 'COUNTRY',
    effectiveScope: 'COUNTRY',
    country: { code, displayName: code, version: 'match-country-v1' },
    queueKey: queueKeyFor({ scope: 'COUNTRY', countryCode: code }),
    countryPolicyVersion: 'match-country-v1'
});

test('queue keys isolate Global, same-country and different-country searches', () => {
    assert.equal(queueKeyFor({ scope: 'GLOBAL' }), 'match:global');
    assert.equal(queueKeyFor({ scope: 'COUNTRY', countryCode: 'TR' }), 'match:country:TR');
    assert.notEqual(queueKeyFor({ scope: 'COUNTRY', countryCode: 'TR' }), queueKeyFor({ scope: 'COUNTRY', countryCode: 'DE' }));
    assert.notEqual(queueKeyFor({ scope: 'GLOBAL' }), queueKeyFor({ scope: 'COUNTRY', countryCode: 'TR' }));
});

test('country resolution uses only canonical Wave 06 data and rejects stale/unavailable records', async () => {
    const eligiblePool = { query: async () => ({ rows: [{ country_code: 'TR', display_name: 'T�rkiye', status: 'eligible', confidence: 'policy_verified', policy_version: 'match-country-v1' }] }) };
    const eligible = await resolveCanonicalMatchScope({ pool: eligiblePool, userId: 'u1', requestedScope: 'COUNTRY' });
    assert.equal(eligible.ok, true);
    assert.equal(eligible.queueKey, 'match:country:TR');
    const stalePool = { query: async () => ({ rows: [{ country_code: 'TR', status: 'stale', confidence: 'policy_verified' }] }) };
    assert.equal((await resolveCanonicalMatchScope({ pool: stalePool, userId: 'u1', requestedScope: 'COUNTRY' })).code, 'MATCH_COUNTRY_STALE');
    const unavailablePool = { query: async () => ({ rows: [] }) };
    assert.equal((await resolveCanonicalMatchScope({ pool: unavailablePool, userId: 'u1', requestedScope: 'COUNTRY' })).code, 'MATCH_COUNTRY_UNAVAILABLE');
});

test('client cannot submit a forged country and scope change requires complete identity', () => {
    assert.equal(validateWsEvent({ type: 'joinQueue', protocolVersion: 1, searchId: id(1), commandId: id(2), scope: 'COUNTRY', countryCode: 'DE' }).code, 'UNEXPECTED_FIELD');
    assert.equal(validateWsEvent({ type: 'changeMatchScope', protocolVersion: 1, fromSearchId: id(1), searchId: id(3), commandId: id(4), scope: 'GLOBAL' }).ok, true);
    assert.equal(validateWsEvent({ type: 'changeMatchScope', protocolVersion: 1, searchId: id(3), commandId: id(4), scope: 'GLOBAL' }).code, 'INVALID_INPUT');
});

test('scope replacement atomically invalidates the old search and preserves one active record', () => {
    const lifecycle = createSearchLifecycle({ setTimer: () => 1, clearTimer() {} });
    lifecycle.begin({ userId: 'u1', connectionId: 'c1', searchId: id(1), commandId: id(2), scopeContext: country('TR') });
    const changed = lifecycle.replace({
        userId: 'u1', connectionId: 'c1', fromSearchId: id(1), searchId: id(3), commandId: id(4),
        scopeContext: { requestedScope: 'GLOBAL', effectiveScope: 'GLOBAL', queueKey: 'match:global' }
    });
    assert.equal(changed.kind, 'accepted');
    assert.equal(changed.previous.phase, 'cancelled');
    assert.equal(lifecycle.getByUser('u1').searchId, id(3));
    assert.equal(lifecycle.getByUser('u1').effectiveMatchScope, 'GLOBAL');
    assert.equal(lifecycle.replace({ userId: 'u1', connectionId: 'c1', fromSearchId: id(1), searchId: id(5), commandId: id(6), scopeContext: country('DE') }).kind, 'stale');
});

test('a second connection cannot take over an active search through scope change', () => {
    const lifecycle = createSearchLifecycle({ setTimer: () => 1, clearTimer() {} });
    lifecycle.begin({ userId: 'u1', connectionId: 'owner', searchId: id(1), commandId: id(2), scopeContext: country('TR') });
    const attempt = lifecycle.replace({
        userId: 'u1', connectionId: 'other', fromSearchId: id(1), searchId: id(3), commandId: id(4),
        scopeContext: { requestedScope: 'GLOBAL', effectiveScope: 'GLOBAL', queueKey: 'match:global' }
    });
    assert.equal(attempt.kind, 'stale');
    assert.equal(lifecycle.getByUser('u1').connectionId, 'owner');
    assert.equal(lifecycle.getByUser('u1').effectiveMatchScope, 'COUNTRY');
});

test('country fallback fires once and never changes scope automatically', () => {
    let now = 0;
    const scheduled = [];
    const events = [];
    const lifecycle = createSearchLifecycle({
        now: () => now,
        fallbackDelayMs: 30000,
        setTimer: (fn, ms) => { scheduled.push({ fn, ms }); return scheduled.length; },
        clearTimer() {},
        onFallback: (_record, event) => events.push(event)
    });
    lifecycle.begin({ userId: 'u1', connectionId: 'c1', searchId: id(1), commandId: id(2), scopeContext: country('TR') });
    const fallback = scheduled.find((item) => item.ms === 30000);
    now = 30000;
    fallback.fn();
    fallback.fn();
    assert.equal(events.length, 1);
    assert.equal(lifecycle.getByUser('u1').effectiveMatchScope, 'COUNTRY');
    assert.equal(lifecycle.getByUser('u1').fallbackStatus, 'eligible');
});

test('process-memory scoped queues fail closed in shared topology', () => {
    assert.equal(assertMatchScopeTopology({ topology: 'single' }), true);
    assert.throws(() => assertMatchScopeTopology({ topology: 'shared-db' }), { code: 'MATCH_SCOPE_REQUIRES_SINGLE_INSTANCE' });
});

test('integration pairing filters by exact queue key and never reads legal acceptance country', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    const scopeSource = fs.readFileSync(path.join(__dirname, '..', 'utils', 'matchScope.js'), 'utf8');
    assert.match(source, /p\.queueKey !== me\.queueKey/);
    assert.match(source, /searchLifecycle\.replace/);
    assert.match(source, /country_fallback_available/);
    assert.match(scopeSource, /FROM user_match_country/);
    assert.doesNotMatch(scopeSource, /legal_acceptances|location_country/);
});

test('bounded admin summary suppresses low-volume country cohorts and exposes no user drilldown', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'admin.js'), 'utf8');
    assert.match(source, /\/analytics\/match-scopes/);
    assert.match(source, /HAVING COUNT\(DISTINCT user_id\) >= \$3/);
    assert.match(source, /lowVolumeCountries: 'suppressed'/);
    assert.match(source, /userDrilldown: false/);
});
