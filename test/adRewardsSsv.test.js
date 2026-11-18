const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
// db.js refuses to load without a connection string; tests never query it.
process.env.DATABASE_URL ||= 'postgres://user:pass@localhost:5432/test';
const adRewards = require('../utils/adRewards');
// Pulls in the pure outcome -> HTTP status mapping used by the SSV route.
const adsRouter = require('../routes/ads');

// Self-generated ECDSA key pair stands in for Google's verifier keys; no network.
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString('utf8');
const KEYS = adRewards.normalizeVerifierKeys({ keys: [{ key_id: '1', pem: PUBLIC_PEM }] });
const loadKeys = async () => KEYS;

const NOW = new Date('2026-05-10T21:30:00.000Z');
const DAY = '2026-05-11';
const USER = '00000000-0000-4000-8000-000000000001';
const NONCE = '00000000-0000-4000-8000-000000000009';

const CONFIG = adRewards.resolveSsvConfig({
    MATCH_QUOTA_ENABLED: 'true',
    MATCH_WELCOME_FREE: '30',
    MATCH_DAILY_FREE: '10',
    ADMOB_SSV_ENABLED: 'true',
    ADMOB_REWARDED_AD_UNITS: 'unit-1,unit-2',
    AD_REWARD_MATCHES: '3',
    AD_DAILY_MAX: '2'
});

const signCallbackQuery = (signingKey, params) => {
    const search = new URLSearchParams(params);
    const signedContent = [...search.entries()].map(([key, value]) => `${key}=${value}`).join('&');
    const signature = crypto.sign('sha256', Buffer.from(signedContent, 'utf8'), signingKey);
    return `${signedContent}&signature=${signature.toString('base64url')}`;
};

const callbackQuery = ({ overrides = {}, signingKey = privateKey } = {}) => signCallbackQuery(signingKey, {
    ad_unit: 'unit-1',
    reward_amount: '3',
    transaction_id: 'tx-1',
    user_id: USER,
    custom_data: NONCE,
    key_id: '1',
    ...overrides
});

// In-memory transactional fake for the handful of SQL statements the callback
// issues: BEGIN snapshots, ROLLBACK restores, COMMIT drops the snapshot.
const createFakeSsvDb = ({ session, quota, ledger = [] } = {}) => {
    const qrow = {
        welcome_remaining: quota?.welcome ?? 0,
        day_key: quota?.dayKey || DAY,
        daily_used: quota?.dailyUsed ?? 0,
        bonus_balance: quota?.bonus ?? 0,
        ads_today: quota?.adsToday ?? 0
    };
    let created = Boolean(quota?.dayKey);
    const sessions = new Map();
    if (session) {
        sessions.set(session.nonce, { user_id: session.userId, expires_at: session.expiresAt, used_at: null });
    }
    const ledgerRows = ledger.map((entry) => ({ ...entry }));
    let snapshot = null;
    let connectCount = 0;
    const client = {
        release: () => {},
        query: async (sql, params = []) => {
            const text = String(sql);
            if (text === 'BEGIN') {
                snapshot = JSON.stringify({ qrow, created, ledgerRows, sessions: [...sessions] });
                return { rows: [] };
            }
            if (text === 'COMMIT') {
                snapshot = null;
                return { rows: [] };
            }
            if (text === 'ROLLBACK') {
                if (snapshot) {
                    const restored = JSON.parse(snapshot);
                    Object.assign(qrow, restored.qrow);
                    created = restored.created;
                    ledgerRows.splice(0, ledgerRows.length, ...restored.ledgerRows);
                    sessions.clear();
                    for (const [key, value] of restored.sessions) sessions.set(key, value);
                    snapshot = null;
                }
                return { rows: [] };
            }
            if (text.startsWith('SELECT user_id, expires_at, used_at FROM ad_reward_sessions')) {
                const found = sessions.get(params[0]);
                return { rows: found ? [{ user_id: found.user_id, expires_at: found.expires_at, used_at: found.used_at }] : [] };
            }
            if (text.startsWith('INSERT INTO ad_reward_ledger')) {
                const [userId, transactionId, adUnit, rewardAmount, nonce] = params;
                if (ledgerRows.some((entry) => entry.transaction_id === transactionId)) return { rows: [] };
                ledgerRows.push({ user_id: userId, transaction_id: transactionId, ad_unit: adUnit, reward_amount: rewardAmount, nonce });
                return { rows: [{ id: ledgerRows.length }] };
            }
            if (text.startsWith('INSERT INTO match_quota')) {
                const [, welcomeFree, dayKey] = params;
                if (!created) {
                    created = true;
                    qrow.welcome_remaining = welcomeFree;
                    qrow.day_key = dayKey;
                    qrow.daily_used = 0;
                    qrow.ads_today = 0;
                } else if (qrow.day_key !== dayKey) {
                    qrow.day_key = dayKey;
                    qrow.daily_used = 0;
                    qrow.ads_today = 0;
                }
                return { rows: [{ ...qrow }] };
            }
            if (text.includes('bonus_balance = bonus_balance +')) {
                if (qrow.ads_today < params[2]) {
                    qrow.bonus_balance += params[1];
                    qrow.ads_today += 1;
                    return { rows: [{ ...qrow }] };
                }
                return { rows: [] };
            }
            if (text.startsWith('UPDATE ad_reward_sessions SET used_at')) {
                const found = sessions.get(params[0]);
                if (found && !found.used_at) {
                    found.used_at = params[1];
                    return { rows: [] };
                }
                return { rows: [] };
            }
            throw new Error('Unexpected SQL in fake ssv db: ' + text.slice(0, 60));
        }
    };
    return {
        qrow,
        ledgerRows,
        sessionFor: (nonce) => sessions.get(nonce) || null,
        connectCount: () => connectCount,
        db: {
            connect: async () => {
                connectCount += 1;
                return client;
            }
        }
    };
};

test('signed content is the query string minus the signature parameter, bytes untouched', () => {
    assert.equal(adRewards.extractSignedContent('a=1&signature=XYZ&b=2'), 'a=1&b=2');
    assert.equal(adRewards.extractSignedContent('signature=XYZ'), '');
    assert.equal(adRewards.extractSignedContent('ad_unit=x%20y&signature=z'), 'ad_unit=x%20y');
    assert.equal(adRewards.extractSignedContent(''), '');
});

test('verifier keys payload shapes are normalized', () => {
    const shaped = adRewards.normalizeVerifierKeys({ keys: [{ key_id: 'k1', pem: PUBLIC_PEM }] });
    assert.deepEqual(shaped, [{ keyId: 'k1', pem: PUBLIC_PEM }]);
    const bare = adRewards.normalizeVerifierKeys([PUBLIC_PEM]);
    assert.deepEqual(bare, [{ keyId: null, pem: PUBLIC_PEM }]);
    assert.deepEqual(adRewards.normalizeVerifierKeys({ keys: [{ pem: 'no-begin-marker' }] }), []);
    assert.deepEqual(adRewards.normalizeVerifierKeys(null), []);
});

test('ECDSA SHA-256 signature verifies for genuine payload and rejects tampering', () => {
    const query = callbackQuery();
    const signedContent = adRewards.extractSignedContent(query);
    const signature = query.slice(query.indexOf('&signature=') + '&signature='.length);
    assert.equal(adRewards.verifySsvSignature({ signedContent, signature, keys: KEYS, keyId: '1' }), true);
    assert.equal(adRewards.verifySsvSignature({ signedContent, signature, keys: KEYS }), true); // no key_id in query

    const tampered = adRewards.verifySsvSignature({
        signedContent: signedContent + '&extra=1', signature, keys: KEYS, keyId: '1'
    });
    assert.equal(tampered, false);

    const { privateKey: otherKey, publicKey: otherPublic } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const otherQuery = callbackQuery({ signingKey: otherKey });
    const otherSignature = otherQuery.slice(otherQuery.indexOf('&signature=') + '&signature='.length);
    assert.equal(adRewards.verifySsvSignature({ signedContent, signature: otherSignature, keys: KEYS, keyId: '1' }), false);

    // key_id mismatch: keys are filtered to the advertised id
    assert.equal(adRewards.verifySsvSignature({ signedContent, signature, keys: KEYS, keyId: '999' }), false);
    const otherKeys = adRewards.normalizeVerifierKeys({ keys: [{ key_id: '2', pem: otherPublic.export({ type: 'spki', format: 'pem' }).toString('utf8') }] });
    assert.equal(adRewards.verifySsvSignature({ signedContent, signature, keys: otherKeys, keyId: '1' }), false);
    assert.equal(adRewards.verifySsvSignature({ signedContent, signature: 'not-a-signature', keys: KEYS, keyId: '1' }), false);
});

test('verifier key loader caches within ttl and refetches after expiry', async () => {
    let fetchCount = 0;
    const fetchImpl = async () => {
        fetchCount += 1;
        return { ok: true, json: async () => ({ keys: [{ key_id: 'k1', pem: PUBLIC_PEM }] }) };
    };
    let clock = 1000;
    const loader = adRewards.createVerifierKeyLoader({
        fetchImpl, url: 'https://example.test/keys', ttlMs: 60000, now: () => clock
    });
    const first = await loader();
    assert.equal(first[0].keyId, 'k1');
    await loader();
    await loader();
    assert.equal(fetchCount, 1); // served from cache
    clock = 61001;
    await loader();
    assert.equal(fetchCount, 2); // ttl expired
});

test('verifier key loader rejects payloads without usable keys', async () => {
    const loader = adRewards.createVerifierKeyLoader({
        fetchImpl: async () => ({ ok: true, json: async () => ({ keys: [] }) }),
        now: () => 1
    });
    await assert.rejects(loader(), /no usable keys/i);
    const failing = adRewards.createVerifierKeyLoader({
        fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }),
        now: () => 1
    });
    await assert.rejects(failing(), /503/);
});

test('valid callback credits bonus once, marks the nonce used and stays idempotent', async () => {
    const fake = createFakeSsvDb({
        session: { nonce: NONCE, userId: USER, expiresAt: '2026-05-10T22:00:00.000Z' },
        quota: { welcome: 0, dayKey: DAY, dailyUsed: 0, bonus: 0, adsToday: 0 }
    });
    const outcome = await adRewards.processRewardCallback({
        db: fake.db, rawQuery: callbackQuery(), loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(outcome.ok, true);
    assert.equal(outcome.credited, true);
    assert.equal(outcome.quota.bonusBalance, 3);
    assert.equal(outcome.quota.adsToday, 1);
    assert.equal(fake.qrow.bonus_balance, 3);
    assert.equal(fake.qrow.ads_today, 1);
    assert.equal(fake.ledgerRows.length, 1);
    assert.equal(fake.ledgerRows[0].transaction_id, 'tx-1');
    assert.ok(fake.sessionFor(NONCE).used_at);

    // Replay of the same Google callback: the nonce is spent, nothing changes.
    const replay = await adRewards.processRewardCallback({
        db: fake.db, rawQuery: callbackQuery(), loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(replay.ok, false);
    assert.equal(replay.reason, 'nonce_invalid');
    assert.equal(fake.qrow.bonus_balance, 3);
    assert.equal(fake.ledgerRows.length, 1);
});

test('a replayed transaction id after a partial write is rejected by the ledger', async () => {
    // Simulates a crash after the ledger insert but before the nonce was marked
    // used: session is live again, but transaction_id UNIQUE keeps it idempotent.
    const fake = createFakeSsvDb({
        session: { nonce: NONCE, userId: USER, expiresAt: '2026-05-10T22:00:00.000Z' },
        quota: { welcome: 0, dayKey: DAY, dailyUsed: 0, bonus: 0, adsToday: 0 },
        ledger: [{ user_id: USER, transaction_id: 'tx-1', ad_unit: 'unit-1', reward_amount: 3, nonce: NONCE }]
    });
    const outcome = await adRewards.processRewardCallback({
        db: fake.db, rawQuery: callbackQuery(), loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.reason, 'duplicate_transaction');
    assert.equal(fake.qrow.bonus_balance, 0);
    assert.equal(fake.ledgerRows.length, 1);
    assert.equal(fake.sessionFor(NONCE).used_at, null);
});

test('invalid or stale callbacks earn nothing', async () => {
    const liveSession = { nonce: NONCE, userId: USER, expiresAt: '2026-05-10T22:00:00.000Z' };

    const missing = await adRewards.processRewardCallback({
        db: createFakeSsvDb({ session: liveSession }).db,
        rawQuery: 'transaction_id=tx-1&user_id=' + USER,
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(missing.reason, 'invalid_params');

    const badUnit = await adRewards.processRewardCallback({
        db: createFakeSsvDb({ session: liveSession }).db,
        rawQuery: callbackQuery({ overrides: { ad_unit: 'unit-9' } }),
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(badUnit.reason, 'ad_unit_not_allowed');

    const expired = await adRewards.processRewardCallback({
        db: createFakeSsvDb({ session: { ...liveSession, expiresAt: '2026-05-10T21:00:00.000Z' }, quota: { dayKey: DAY } }).db,
        rawQuery: callbackQuery(), loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(expired.reason, 'nonce_invalid');

    const wrongUser = await adRewards.processRewardCallback({
        db: createFakeSsvDb({ session: liveSession, quota: { dayKey: DAY } }).db,
        rawQuery: callbackQuery({ overrides: { user_id: '00000000-0000-4000-8000-000000000002' } }),
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(wrongUser.reason, 'nonce_invalid');

    const unknownNonce = await adRewards.processRewardCallback({
        db: createFakeSsvDb({ quota: { dayKey: DAY } }).db,
        rawQuery: callbackQuery({ overrides: { custom_data: 'nonce-no-session' } }),
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(unknownNonce.reason, 'nonce_invalid');
});

test('invalid signature touches no data', async () => {
    const fake = createFakeSsvDb({
        session: { nonce: NONCE, userId: USER, expiresAt: '2026-05-10T22:00:00.000Z' },
        quota: { welcome: 0, dayKey: DAY, dailyUsed: 0, bonus: 0, adsToday: 0 }
    });
    // Signed with a key that is not among the injected verifier keys.
    const { privateKey: rogueKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const outcome = await adRewards.processRewardCallback({
        db: fake.db,
        rawQuery: callbackQuery({ overrides: { transaction_id: 'tx-forged' }, signingKey: rogueKey }),
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.reason, 'signature_invalid');
    assert.equal(fake.connectCount(), 0); // rejected before any transaction
    assert.equal(fake.qrow.bonus_balance, 0);
    assert.equal(fake.ledgerRows.length, 0);
});

test('daily ad cap stops crediting and rolls the ledger back', async () => {
    const fake = createFakeSsvDb({
        session: { nonce: NONCE, userId: USER, expiresAt: '2026-05-10T22:00:00.000Z' },
        quota: { welcome: 0, dayKey: DAY, dailyUsed: 0, bonus: 6, adsToday: 2 } // cap is 2
    });
    const outcome = await adRewards.processRewardCallback({
        db: fake.db, rawQuery: callbackQuery(), loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(outcome.ok, true);
    assert.equal(outcome.credited, false);
    assert.equal(outcome.reason, 'AD_LIMIT_REACHED');
    assert.equal(fake.qrow.bonus_balance, 6);
    assert.equal(fake.qrow.ads_today, 2);
    assert.equal(fake.ledgerRows.length, 0); // insert rolled back
    assert.equal(fake.sessionFor(NONCE).used_at, null); // nonce stays usable
});

test('ssv disabled short-circuits without touching the db', async () => {
    const fake = createFakeSsvDb({});
    const outcome = await adRewards.processRewardCallback({
        db: fake.db,
        rawQuery: callbackQuery(),
        loadKeys,
        now: NOW,
        config: adRewards.resolveSsvConfig({ ADMOB_SSV_ENABLED: 'false' })
    });
    assert.deepEqual(outcome, { ok: true, credited: false, reason: 'ssv_disabled' });
    assert.equal(fake.connectCount(), 0);
});

// HTTP status contract: transient failures (verifier keys unavailable, any
// unexpected exception the route catches) must answer 503 so AdMob retries;
// definitive verification outcomes must stay at 200 so Google never retries
// invalid input. processRewardCallback flags the transient keys failure.
test('transient keys_unavailable is flagged retryable and maps to 503', async () => {
    const outcome = await adRewards.processRewardCallback({
        db: createFakeSsvDb({}).db,
        rawQuery: callbackQuery(),
        loadKeys: async () => { throw new Error('keys endpoint unreachable'); },
        now: NOW, config: CONFIG
    });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.reason, 'keys_unavailable');
    assert.equal(outcome.transient, true);
    assert.equal(adsRouter.ssvHttpStatus(outcome), 503);
});

test('definitive outcomes stay unflagged and map to 200', async () => {
    const liveSession = { nonce: NONCE, userId: USER, expiresAt: '2026-05-10T22:00:00.000Z' };

    const invalidParams = await adRewards.processRewardCallback({
        db: createFakeSsvDb({}).db,
        rawQuery: 'transaction_id=tx-1&user_id=' + USER,
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(invalidParams.reason, 'invalid_params');

    const adUnit = await adRewards.processRewardCallback({
        db: createFakeSsvDb({ session: liveSession }).db,
        rawQuery: callbackQuery({ overrides: { ad_unit: 'unit-9' } }),
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(adUnit.reason, 'ad_unit_not_allowed');

    const { privateKey: rogueKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const forged = await adRewards.processRewardCallback({
        db: createFakeSsvDb({ session: liveSession }).db,
        rawQuery: callbackQuery({ overrides: { transaction_id: 'tx-forged' }, signingKey: rogueKey }),
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(forged.reason, 'signature_invalid');

    const staleNonce = await adRewards.processRewardCallback({
        db: createFakeSsvDb({ quota: { dayKey: DAY } }).db,
        rawQuery: callbackQuery({ overrides: { custom_data: 'nonce-no-session' } }),
        loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(staleNonce.reason, 'nonce_invalid');

    const duplicate = await adRewards.processRewardCallback({
        db: createFakeSsvDb({
            session: liveSession,
            quota: { dayKey: DAY },
            ledger: [{ user_id: USER, transaction_id: 'tx-1', ad_unit: 'unit-1', reward_amount: 3, nonce: NONCE }]
        }).db,
        rawQuery: callbackQuery(), loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(duplicate.reason, 'duplicate_transaction');

    const dailyCap = await adRewards.processRewardCallback({
        db: createFakeSsvDb({
            session: liveSession,
            quota: { welcome: 0, dayKey: DAY, dailyUsed: 0, bonus: 6, adsToday: 2 } // cap is 2
        }).db,
        rawQuery: callbackQuery(), loadKeys, now: NOW, config: CONFIG
    });
    assert.equal(dailyCap.reason, 'AD_LIMIT_REACHED');

    const disabled = await adRewards.processRewardCallback({
        db: createFakeSsvDb({}).db,
        rawQuery: callbackQuery(), loadKeys, now: NOW,
        config: adRewards.resolveSsvConfig({ ADMOB_SSV_ENABLED: 'false' })
    });
    assert.equal(disabled.reason, 'ssv_disabled');

    for (const outcome of [invalidParams, adUnit, forged, staleNonce, duplicate, dailyCap, disabled]) {
        assert.notEqual(outcome.transient, true);
        assert.equal(adsRouter.ssvHttpStatus(outcome), 200);
    }
    // Successful credit stays at 200 as well.
    const credited = { ok: true, credited: true, reason: null };
    assert.equal(adsRouter.ssvHttpStatus(credited), 200);
});

// In-memory fake for the reward-session housekeeping SQL (capacity + purge).
// The purge statement runs NOW() inside SQL; the fake approximates it with a
// fixed clock equal to NOW.
const createCapacityDb = ({ sessions = [], now = NOW } = {}) => {
    const rows = sessions.map((entry) => ({
        nonce: entry.nonce,
        user_id: entry.userId || USER,
        created_at: entry.createdAt,
        expires_at: entry.expiresAt,
        used_at: entry.usedAt || null
    }));
    const fakeNow = new Date(now).getTime();
    return {
        rows,
        query: async (sql, params = []) => {
            const text = String(sql);
            if (text.startsWith('SELECT COUNT(*)::int AS active FROM ad_reward_sessions')) {
                const [userId, at] = params;
                const active = rows.filter((row) => row.user_id === userId
                    && !row.used_at
                    && new Date(row.expires_at).getTime() > new Date(at).getTime());
                return { rows: [{ active: active.length }], rowCount: rows.length };
            }
            if (text.startsWith('UPDATE ad_reward_sessions SET used_at = $1 WHERE nonce IN')) {
                const [at, userId, limit] = params;
                const candidates = rows
                    .filter((row) => row.user_id === userId && !row.used_at && new Date(row.expires_at).getTime() > new Date(at).getTime())
                    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
                    .slice(0, Number(limit));
                candidates.forEach((row) => { row.used_at = at; });
                return { rows: [], rowCount: candidates.length };
            }
            if (text.startsWith('DELETE FROM ad_reward_sessions WHERE nonce IN')) {
                const [days, limit] = params;
                const cutoff = fakeNow - Number(days) * 24 * 60 * 60 * 1000;
                const doomed = rows
                    .filter((row) => new Date(row.expires_at).getTime() < cutoff)
                    .slice(0, Number(limit));
                doomed.forEach((row) => rows.splice(rows.indexOf(row), 1));
                return { rows: [], rowCount: doomed.length };
            }
            throw new Error('Unexpected SQL in capacity fake: ' + text.slice(0, 60));
        }
    };
};

const capacitySession = (index, overrides = {}) => ({
    nonce: `nonce-${index}`,
    // Higher index = created later, so nonce-1 is always the oldest.
    createdAt: new Date(new Date(NOW).getTime() - (6 - index) * 60000).toISOString(),
    expiresAt: '2026-05-10T22:00:00.000Z',
    ...overrides
});

test('reward-session capacity allows two live nonces and invalidates the oldest beyond three', async () => {
    const two = createCapacityDb({ sessions: [capacitySession(2), capacitySession(1)] });
    let result = await adRewards.ensureRewardSessionCapacity(two, USER, { now: NOW });
    assert.equal(result.active, 2);
    assert.equal(result.pruned, 0);
    assert.ok(two.rows.every((row) => !row.used_at));

    const three = createCapacityDb({ sessions: [capacitySession(3), capacitySession(2), capacitySession(1)] });
    result = await adRewards.ensureRewardSessionCapacity(three, USER, { now: NOW });
    assert.equal(result.active, 3);
    assert.equal(result.pruned, 1); // oldest (nonce-1) invalidated, room for one new nonce
    assert.ok(three.rows.find((row) => row.nonce === 'nonce-1').used_at);
    assert.ok(!three.rows.find((row) => row.nonce === 'nonce-2').used_at);
    assert.ok(!three.rows.find((row) => row.nonce === 'nonce-3').used_at);
});

test('reward-session capacity trims exactly the overflow of the oldest nonces', async () => {
    const five = createCapacityDb({ sessions: [capacitySession(5), capacitySession(4), capacitySession(3), capacitySession(2), capacitySession(1)] });
    const result = await adRewards.ensureRewardSessionCapacity(five, USER, { now: NOW });
    assert.equal(result.active, 5);
    assert.equal(result.pruned, 3); // 5 live - 3 kept + 1 incoming
    assert.deepEqual(
        five.rows.filter((row) => row.used_at).map((row) => row.nonce).sort(),
        ['nonce-1', 'nonce-2', 'nonce-3']
    );
    assert.deepEqual(
        five.rows.filter((row) => !row.used_at).map((row) => row.nonce).sort(),
        ['nonce-4', 'nonce-5']
    );
});

test('reward-session capacity only counts the requesting user', async () => {
    const other = '00000000-0000-4000-8000-000000000002';
    const fake = createCapacityDb({
        sessions: [capacitySession(1, { userId: other }), capacitySession(2, { userId: other }), capacitySession(3, { userId: other })]
    });
    const result = await adRewards.ensureRewardSessionCapacity(fake, USER, { now: NOW });
    assert.equal(result.active, 0);
    assert.equal(result.pruned, 0);
    assert.ok(fake.rows.every((row) => !row.used_at));
});

test('opportunistic purge deletes only sessions expired over 7 days, bounded by limit', async () => {
    const now = new Date(NOW).getTime();
    const day = 24 * 60 * 60 * 1000;
    const fake = createCapacityDb({
        sessions: [
            { nonce: 'ancient-1', createdAt: '2026-04-01T00:00:00.000Z', expiresAt: new Date(now - 8 * day).toISOString() },
            { nonce: 'boundary', createdAt: '2026-04-02T00:00:00.000Z', expiresAt: new Date(now - 7 * day).toISOString() }, // exactly 7d: kept
            { nonce: 'recent', createdAt: '2026-05-10T00:00:00.000Z', expiresAt: '2026-05-10T22:00:00.000Z' },
            { nonce: 'spent-long-ago', createdAt: '2026-04-03T00:00:00.000Z', expiresAt: new Date(now - 30 * day).toISOString(), usedAt: new Date(now - 30 * day).toISOString() }
        ]
    });
    const result = await adRewards.purgeExpiredRewardSessions(fake);
    assert.equal(result.deleted, 2);
    assert.deepEqual(fake.rows.map((row) => row.nonce).sort(), ['boundary', 'recent']);

    const batched = createCapacityDb({
        sessions: [
            { nonce: 'old-a', createdAt: '2026-04-01T00:00:00.000Z', expiresAt: new Date(now - 9 * day).toISOString() },
            { nonce: 'old-b', createdAt: '2026-04-02T00:00:00.000Z', expiresAt: new Date(now - 8 * day).toISOString() },
            { nonce: 'old-c', createdAt: '2026-04-03T00:00:00.000Z', expiresAt: new Date(now - 10 * day).toISOString() }
        ]
    });
    const limited = await adRewards.purgeExpiredRewardSessions(batched, { limit: 2 });
    assert.equal(limited.deleted, 2);
    assert.equal(batched.rows.length, 1); // one old row survives until the next batch
});
