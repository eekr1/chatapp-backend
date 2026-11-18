const test = require('node:test');
const assert = require('node:assert/strict');
const matchQuota = require('../utils/matchQuota');

// Europe/Istanbul is a fixed UTC+3 zone, so these instants are stable.
const NOW = '2026-05-10T21:30:00.000Z'; // 2026-05-11 00:30 in Istanbul
const PREV_DAY_NOW = '2026-05-10T20:59:59.000Z'; // 2026-05-10 23:59:59 local
const DAY = '2026-05-11';
const PREV_DAY = '2026-05-10';
const USER = '00000000-0000-4000-8000-000000000001';

const QUOTA_KEYS = [
    'enabled', 'welcomeRemaining', 'dailyLimit', 'dailyUsed', 'dailyRemaining',
    'bonusBalance', 'totalRemaining', 'resetsAt', 'adsToday', 'adsDailyMax',
    'rewardPerAd', 'rewardedAvailable'
].sort();

const ENV_KEYS = [
    'MATCH_QUOTA_ENABLED', 'MATCH_WELCOME_FREE', 'MATCH_DAILY_FREE',
    'AD_REWARD_MATCHES', 'AD_DAILY_MAX', 'ADMOB_SSV_ENABLED'
];

const withEnv = (overrides, fn) => {
    const saved = {};
    for (const key of ENV_KEYS) saved[key] = process.env[key];
    for (const key of ENV_KEYS) delete process.env[key];
    // Pin the numbers these tests were written against, independent of production defaults.
    const pinned = { MATCH_WELCOME_FREE: '30', MATCH_DAILY_FREE: '10', ...overrides };
    for (const [key, value] of Object.entries(pinned)) process.env[key] = value;
    return Promise.resolve()
        .then(fn)
        .finally(() => {
            for (const key of ENV_KEYS) {
                if (saved[key] === undefined) delete process.env[key];
                else process.env[key] = saved[key];
            }
        });
};

// In-memory stand-in for the handful of SQL statements matchQuota.js issues.
const rowView = (row) => ({
    welcome_remaining: row.welcome_remaining,
    day_key: row.day_key,
    daily_used: row.daily_used,
    bonus_balance: row.bonus_balance,
    ads_today: row.ads_today
});

const createFakeDb = (state = {}) => {
    const row = {
        welcome_remaining: state.welcome ?? 0,
        day_key: state.dayKey || null,
        daily_used: state.dailyUsed ?? 0,
        bonus_balance: state.bonus ?? 0,
        ads_today: state.adsToday ?? 0
    };
    let created = Boolean(state.dayKey);
    const calls = [];
    return {
        row,
        calls,
        query: async (sql, params = []) => {
            calls.push(String(sql));
            if (sql.startsWith('INSERT INTO match_quota')) {
                const [, welcomeFree, dayKey] = params;
                if (!created) {
                    created = true;
                    row.welcome_remaining = welcomeFree;
                    row.day_key = dayKey;
                    row.daily_used = 0;
                    row.ads_today = 0;
                } else if (row.day_key !== dayKey) {
                    row.day_key = dayKey;
                    row.daily_used = 0;
                    row.ads_today = 0;
                }
                return { rows: [rowView(row)] };
            }
            if (sql.includes('welcome_remaining = welcome_remaining - 1')) {
                if (row.welcome_remaining > 0) {
                    row.welcome_remaining -= 1;
                    return { rows: [rowView(row)] };
                }
                return { rows: [] };
            }
            if (sql.includes('daily_used = daily_used + 1')) {
                if (row.day_key === params[1] && row.daily_used < params[2]) {
                    row.daily_used += 1;
                    return { rows: [rowView(row)] };
                }
                return { rows: [] };
            }
            if (sql.includes('bonus_balance = bonus_balance - 1')) {
                if (row.bonus_balance > 0) {
                    row.bonus_balance -= 1;
                    return { rows: [rowView(row)] };
                }
                return { rows: [] };
            }
            if (sql.includes('bonus_balance = bonus_balance +')) {
                if (row.ads_today < params[2]) {
                    row.bonus_balance += params[1];
                    row.ads_today += 1;
                    return { rows: [rowView(row)] };
                }
                return { rows: [] };
            }
            throw new Error('Unexpected SQL in fake db: ' + sql.slice(0, 60));
        }
    };
};

test('day key and reset time follow Europe/Istanbul', () => {
    assert.equal(matchQuota.dayKeyFor(NOW), DAY);
    assert.equal(matchQuota.dayKeyFor(PREV_DAY_NOW), PREV_DAY);
    assert.equal(matchQuota.dayKeyFor('2026-01-01T00:30:00.000Z'), '2026-01-01'); // 03:30 local
    assert.equal(matchQuota.nextMidnightIso(NOW), '2026-05-11T21:00:00.000Z');
});

test('quota object keeps the shared JSON contract', async () => {
    const db = createFakeDb({ welcome: 12, dayKey: DAY, dailyUsed: 3, bonus: 7, adsToday: 1 });
    const quota = await withEnv({ ADMOB_SSV_ENABLED: 'true' }, () => matchQuota.getQuota(db, USER, { now: NOW }));
    assert.deepEqual(Object.keys(quota).sort(), QUOTA_KEYS);
    assert.equal(quota.enabled, true);
    assert.equal(quota.welcomeRemaining, 12);
    assert.equal(quota.dailyLimit, 10);
    assert.equal(quota.dailyUsed, 3);
    assert.equal(quota.dailyRemaining, 7);
    assert.equal(quota.bonusBalance, 7);
    assert.equal(quota.totalRemaining, 12 + 7 + 7);
    assert.equal(quota.adsToday, 1);
    assert.equal(quota.adsDailyMax, 5);
    assert.equal(quota.rewardPerAd, 3);
    assert.equal(quota.rewardedAvailable, true);
    assert.equal(quota.resetsAt, '2026-05-11T21:00:00.000Z');
});

test('first read creates the row with the welcome grant', async () => {
    const db = createFakeDb();
    const quota = await withEnv({}, () => matchQuota.getQuota(db, USER, { now: NOW }));
    assert.equal(db.row.welcome_remaining, 30);
    assert.equal(db.row.day_key, DAY);
    assert.equal(quota.welcomeRemaining, 30);
    assert.equal(quota.totalRemaining, 40);
});

test('lazy reset zeroes daily_used and ads_today on day change, keeps welcome and bonus', async () => {
    const db = createFakeDb({ welcome: 12, dayKey: PREV_DAY, dailyUsed: 10, bonus: 7, adsToday: 5 });
    const quota = await withEnv({}, () => matchQuota.getQuota(db, USER, { now: NOW }));
    assert.equal(db.row.day_key, DAY);
    assert.equal(db.row.daily_used, 0);
    assert.equal(db.row.ads_today, 0);
    assert.equal(db.row.welcome_remaining, 12);
    assert.equal(db.row.bonus_balance, 7);
    assert.equal(quota.dailyUsed, 0);
    assert.equal(quota.adsToday, 0);
    assert.equal(quota.totalRemaining, 12 + 10 + 7);
});

test('no reset inside the same day', async () => {
    const db = createFakeDb({ welcome: 5, dayKey: DAY, dailyUsed: 4, bonus: 0, adsToday: 2 });
    const quota = await withEnv({}, () => matchQuota.getQuota(db, USER, { now: '2026-05-11T08:00:00.000Z' }));
    assert.equal(quota.dailyUsed, 4);
    assert.equal(quota.adsToday, 2);
});

test('consumption order is welcome first, then daily, then bonus', async () => {
    const db = createFakeDb({ welcome: 2, dayKey: DAY, dailyUsed: 0, bonus: 1, adsToday: 0 });
    await withEnv({ MATCH_DAILY_FREE: '2' }, async () => {
        const steps = [];
        for (let i = 0; i < 6; i += 1) {
            const result = await matchQuota.consumeMatch(db, USER, { now: NOW });
            steps.push({ consumed: result.consumed, quota: result.quota });
        }
        assert.equal(steps[0].consumed, true);
        assert.equal(steps[0].quota.welcomeRemaining, 1);
        assert.equal(steps[0].quota.dailyUsed, 0);
        assert.equal(steps[1].consumed, true);
        assert.equal(steps[1].quota.welcomeRemaining, 0);
        assert.equal(steps[2].consumed, true);
        assert.equal(steps[2].quota.dailyUsed, 1); // daily bucket now starts
        assert.equal(steps[3].consumed, true);
        assert.equal(steps[3].quota.dailyUsed, 2);
        assert.equal(steps[4].consumed, true);
        assert.equal(steps[4].quota.bonusBalance, 0); // bonus is last
        assert.equal(steps[5].consumed, false); // nothing left
        assert.equal(steps[5].quota.totalRemaining, 0);
    });
});

test('daily cap blocks the daily bucket and consumption falls through to bonus', async () => {
    const db = createFakeDb({ welcome: 0, dayKey: DAY, dailyUsed: 2, bonus: 3, adsToday: 0 });
    await withEnv({ MATCH_DAILY_FREE: '2' }, async () => {
        const result = await matchQuota.consumeMatch(db, USER, { now: NOW });
        assert.equal(result.consumed, true);
        assert.equal(result.quota.bonusBalance, 2);
        assert.equal(result.quota.dailyUsed, 2); // stayed capped
        assert.equal(db.row.daily_used, 2);
    });
});

test('zero rights: cannot start a search and consume is a no-op', async () => {
    const db = createFakeDb({ welcome: 0, dayKey: DAY, dailyUsed: 10, bonus: 0, adsToday: 0 });
    await withEnv({ MATCH_DAILY_FREE: '10' }, async () => {
        const eligibility = await matchQuota.canStartSearch(db, USER, { now: NOW });
        assert.equal(eligibility.ok, false);
        assert.equal(eligibility.quota.totalRemaining, 0);
        const result = await matchQuota.consumeMatch(db, USER, { now: NOW });
        assert.equal(result.consumed, false);
        assert.equal(db.row.welcome_remaining, 0);
        assert.equal(db.row.bonus_balance, 0);
    });
});

test('MATCH_QUOTA_ENABLED=false makes everything free without touching the db', async () => {
    const db = createFakeDb({ welcome: 0, dayKey: DAY, dailyUsed: 10, bonus: 0, adsToday: 0 });
    await withEnv({ MATCH_QUOTA_ENABLED: 'false' }, async () => {
        const eligibility = await matchQuota.canStartSearch(db, USER, { now: NOW });
        assert.deepEqual(eligibility, { ok: true, quota: null });
        const result = await matchQuota.consumeMatch(db, USER, { now: NOW });
        assert.deepEqual(result, { consumed: false, quota: null });
        assert.equal(db.calls.length, 0);
    });
});

test('rewarded ads credit bonus and stop at the daily cap', async () => {
    const db = createFakeDb({ welcome: 0, dayKey: DAY, dailyUsed: 0, bonus: 0, adsToday: 0 });
    await withEnv({ ADMOB_SSV_ENABLED: 'true', AD_DAILY_MAX: '1', AD_REWARD_MATCHES: '3' }, async () => {
        const first = await matchQuota.creditAdReward(db, USER, { now: NOW });
        assert.equal(first.credited, true);
        assert.equal(first.quota.bonusBalance, 3);
        assert.equal(first.quota.adsToday, 1);
        assert.equal(first.quota.rewardedAvailable, false); // cap reached
        const second = await matchQuota.creditAdReward(db, USER, { now: NOW });
        assert.equal(second.credited, false);
        assert.equal(second.reason, 'AD_LIMIT_REACHED');
        assert.equal(db.row.bonus_balance, 3);
        assert.equal(db.row.ads_today, 1);
    });
});
