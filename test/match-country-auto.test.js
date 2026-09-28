const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { normalizeIp, resolveClientIp } = require('../utils/clientIp');
const { resolveLocalCountry } = require('../utils/localGeoCountry');
const { ensureUserMatchCountry } = require('../utils/matchCountryService');

const eligibleRow = (overrides = {}) => ({
    country_code: 'TR',
    source: 'local:user-country',
    status: 'eligible',
    confidence: 'policy_verified',
    source_observed_at: new Date('2026-09-28T00:00:00Z'),
    resolved_at: new Date('2026-09-28T00:00:00Z'),
    updated_at: new Date('2026-09-28T00:00:00Z'),
    policy_version: 'match-country-v1',
    ...overrides
});

const createPool = ({ current = null, latestIp = null } = {}) => {
    const writes = [];
    return {
        writes,
        async query(sql, params) {
            if (/FROM user_match_country/.test(sql)) return { rows: current ? [current] : [] };
            if (/FROM legal_acceptances/.test(sql)) return { rows: latestIp ? [{ ip: latestIp }] : [] };
            if (/INSERT INTO user_match_country/.test(sql)) {
                const row = {
                    country_code: params[1],
                    source: params[2],
                    status: params[3],
                    confidence: params[4],
                    source_observed_at: params[5],
                    resolved_at: params[5],
                    updated_at: params[5],
                    policy_version: params[6]
                };
                writes.push(row);
                return { rows: [row] };
            }
            throw new Error(`Unexpected query: ${sql}`);
        }
    };
};

test('trusted proxy-aware client IP resolution rejects malformed values and spoofed left entries', () => {
    assert.equal(normalizeIp('::ffff:203.0.113.9'), '203.0.113.9');
    assert.equal(normalizeIp('[2606:4700:4700::1111]:443'), '2606:4700:4700::1111');
    assert.equal(normalizeIp('not-an-ip'), null);

    const req = {
        headers: { 'x-forwarded-for': '198.51.100.7, 203.0.113.9' },
        socket: { remoteAddress: '10.0.0.5' }
    };
    assert.equal(resolveClientIp(req, { NODE_ENV: 'production' }), '203.0.113.9');
    assert.equal(resolveClientIp(req, { NODE_ENV: 'development' }), '10.0.0.5');
    assert.equal(resolveClientIp(req, { TRUST_PROXY_HOPS: '2' }), '198.51.100.7');
});

test('committed local database resolves public IPv4 and IPv6 without accepting private addresses', () => {
    assert.deepEqual(resolveLocalCountry('8.8.8.8'), {
        ok: true,
        countryCode: 'US',
        source: 'local:user-country'
    });
    assert.deepEqual(resolveLocalCountry('2606:4700:4700::1111'), {
        ok: true,
        countryCode: 'US',
        source: 'local:user-country'
    });
    assert.deepEqual(resolveLocalCountry('192.168.1.10'), {
        ok: false,
        countryCode: null,
        source: 'private'
    });
});

test('successful local resolution creates an eligible canonical country record', async () => {
    const pool = createPool();
    const now = new Date('2026-09-28T12:00:00Z');
    const result = await ensureUserMatchCountry({
        pool,
        userId: 'user-1',
        ip: '8.8.8.8',
        now,
        resolver: () => ({ ok: true, countryCode: 'US', source: 'local:user-country' })
    });
    assert.equal(result.status, 'eligible');
    assert.equal(result.country_code, 'US');
    assert.equal(result.confidence, 'policy_verified');
    assert.equal(pool.writes.length, 1);
});

test('lookup gaps preserve an existing verified country and never downgrade it', async () => {
    const current = eligibleRow();
    const pool = createPool({ current });
    const result = await ensureUserMatchCountry({
        pool,
        userId: 'user-1',
        ip: '192.168.1.10',
        now: new Date('2026-09-28T12:00:00Z'),
        resolver: () => ({ ok: false, countryCode: null, source: 'private' })
    });
    assert.equal(result.country_code, 'TR');
    assert.equal(result.refreshDeferred, true);
    assert.equal(pool.writes.length, 0);
});

test('missing country becomes unavailable without storing the source IP', async () => {
    const pool = createPool({ latestIp: '192.168.1.10' });
    const result = await ensureUserMatchCountry({
        pool,
        userId: 'user-1',
        now: new Date('2026-09-28T12:00:00Z'),
        resolver: () => ({ ok: false, countryCode: null, source: 'private' })
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.country_code, null);
    assert.equal(pool.writes.length, 1);
    assert.equal(JSON.stringify(pool.writes).includes('192.168.1.10'), false);
});

test('country automation is wired into auth, profile, WebSocket and startup without an external geo provider', () => {
    const root = path.join(__dirname, '..');
    const auth = fs.readFileSync(path.join(root, 'routes', 'auth.js'), 'utf8');
    const profile = fs.readFileSync(path.join(root, 'routes', 'profile.js'), 'utf8');
    const index = fs.readFileSync(path.join(root, 'index.js'), 'utf8');
    const localResolver = fs.readFileSync(path.join(root, 'utils', 'localGeoCountry.js'), 'utf8');

    assert.match(auth, /ensureUserMatchCountry/);
    assert.match(profile, /ensureUserMatchCountry/);
    assert.match(index, /ensureUserMatchCountry/);
    assert.match(index, /startMatchCountryBackfill/);
    assert.doesNotMatch(localResolver, /ipwho|ipapi|geoip|fetch\(|https?:\/\//i);
});
