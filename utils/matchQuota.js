// Match quota (eslesme hakki): welcome + daily (Europe/Istanbul) + rewarded-ad bonus.
// Contract shared with the frontend; do not change JSON shapes unilaterally.
//
// What counts: only a successfully established random match (1 right per side,
// consumed at finalize). Failed searches, cancels, requeues, friend chats and
// DMs never consume rights. Friend messaging is never quota-gated.

const TIMEZONE = 'Europe/Istanbul';
const DAY_MS = 24 * 60 * 60 * 1000;

const toNonNegativeInt = (value, fallback) => {
    if (value === undefined || value === null || String(value).trim() === '') return fallback;
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed < 0) return fallback;
    return Math.round(parsed);
};

const truthyEnv = (value, fallback) => {
    if (value === undefined || value === null || String(value).trim() === '') return fallback;
    return String(value).trim().toLowerCase() === 'true';
};

const resolveConfig = (env = process.env) => ({
    enabled: truthyEnv(env.MATCH_QUOTA_ENABLED, true),
    welcomeFree: toNonNegativeInt(env.MATCH_WELCOME_FREE, 0),
    dailyFree: toNonNegativeInt(env.MATCH_DAILY_FREE, 30),
    adRewardMatches: toNonNegativeInt(env.AD_REWARD_MATCHES, 3),
    adDailyMax: toNonNegativeInt(env.AD_DAILY_MAX, 5),
    admobSsvEnabled: truthyEnv(env.ADMOB_SSV_ENABLED, false)
});

// Wall-clock helpers for the target zone. Uses Intl so a future offset change
// in the zone would keep day keys and reset times correct.
const timeZoneOffsetMs = (date) => {
    const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: TIMEZONE,
        hour12: false,
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    const parts = {};
    for (const part of formatter.formatToParts(date)) parts[part.type] = part.value;
    const asUtc = Date.UTC(
        Number(parts.year),
        Number(parts.month) - 1,
        Number(parts.day),
        Number(parts.hour) % 24,
        Number(parts.minute),
        Number(parts.second)
    );
    return asUtc - date.getTime();
};

const dayKeyFor = (date) => {
    const at = date ? new Date(date) : new Date();
    const shifted = new Date(at.getTime() + timeZoneOffsetMs(at));
    return shifted.toISOString().slice(0, 10);
};

const nextMidnightIso = (date) => {
    const at = date ? new Date(date) : new Date();
    const offset = timeZoneOffsetMs(at);
    const wall = new Date(at.getTime() + offset);
    wall.setUTCHours(0, 0, 0, 0);
    let candidate = new Date(wall.getTime() + DAY_MS - offset);
    // Guard against offset changes exactly at the boundary.
    const todayKey = dayKeyFor(at);
    let guard = 0;
    while (dayKeyFor(candidate) === todayKey && guard < 48) {
        candidate = new Date(candidate.getTime() + 60 * 60 * 1000);
        guard += 1;
    }
    return candidate.toISOString();
};

const QUOTA_COLUMNS = 'welcome_remaining, day_key, daily_used, bonus_balance, ads_today';

// Lazy reset + first-read row creation (welcome grant) in one atomic statement.
const upsertQuotaRow = async (db, userId, dayKey, welcomeFree) => {
    const result = await db.query(
        'INSERT INTO match_quota (user_id, welcome_remaining, day_key, daily_used, bonus_balance, ads_today, updated_at) '
        + 'VALUES ($1, $2, $3, 0, 0, 0, NOW()) '
        + 'ON CONFLICT (user_id) DO UPDATE SET '
        + 'day_key = EXCLUDED.day_key, '
        + 'daily_used = CASE WHEN match_quota.day_key <> EXCLUDED.day_key THEN 0 ELSE match_quota.daily_used END, '
        + 'ads_today = CASE WHEN match_quota.day_key <> EXCLUDED.day_key THEN 0 ELSE match_quota.ads_today END, '
        + 'updated_at = NOW() '
        + 'RETURNING ' + QUOTA_COLUMNS,
        [userId, welcomeFree, dayKey]
    );
    return result.rows[0] || null;
};

const buildQuotaObject = (row, config, date = new Date()) => {
    const dailyLimit = config.dailyFree;
    const dailyUsed = Math.max(0, row.daily_used);
    const dailyRemaining = Math.max(0, dailyLimit - dailyUsed);
    const welcomeRemaining = Math.max(0, row.welcome_remaining);
    const bonusBalance = Math.max(0, row.bonus_balance);
    const adsToday = Math.max(0, row.ads_today);
    return {
        enabled: config.enabled,
        welcomeRemaining,
        dailyLimit,
        dailyUsed,
        dailyRemaining,
        bonusBalance,
        totalRemaining: welcomeRemaining + dailyRemaining + bonusBalance,
        resetsAt: nextMidnightIso(date),
        adsToday,
        adsDailyMax: config.adDailyMax,
        rewardPerAd: config.adRewardMatches,
        rewardedAvailable: config.admobSsvEnabled && adsToday < config.adDailyMax
    };
};

const isEnabled = () => resolveConfig(process.env).enabled;

const getQuota = async (db, userId, options = {}) => {
    const config = resolveConfig(process.env);
    const at = options.now ? new Date(options.now) : new Date();
    const row = await upsertQuotaRow(db, userId, dayKeyFor(at), config.welcomeFree);
    return buildQuotaObject(row, config, at);
};

// Only answers "does a new right need to exist for this queue entry".
// Consumption happens exclusively on successful match finalize.
const canStartSearch = async (db, userId, options = {}) => {
    const config = resolveConfig(process.env);
    if (!config.enabled) return { ok: true, quota: null };
    const at = options.now ? new Date(options.now) : new Date();
    const row = await upsertQuotaRow(db, userId, dayKeyFor(at), config.welcomeFree);
    const quota = buildQuotaObject(row, config, at);
    return { ok: quota.totalRemaining > 0, quota };
};

// Atomic priority consumption: welcome first, then daily (within cap), then
// bonus. Each UPDATE is guarded so concurrent consumers never take the same
// unit twice. Returns consumed=false when no bucket had a unit available.
const consumeMatch = async (db, userId, options = {}) => {
    const config = resolveConfig(process.env);
    if (!config.enabled) return { consumed: false, quota: null };
    const at = options.now ? new Date(options.now) : new Date();
    const dayKey = dayKeyFor(at);
    const currentRow = await upsertQuotaRow(db, userId, dayKey, config.welcomeFree);
    const attempts = [
        {
            sql: 'UPDATE match_quota SET welcome_remaining = welcome_remaining - 1, updated_at = NOW() '
                + 'WHERE user_id = $1 AND welcome_remaining > 0 RETURNING ' + QUOTA_COLUMNS,
            params: [userId]
        },
        {
            sql: 'UPDATE match_quota SET daily_used = daily_used + 1, updated_at = NOW() '
                + 'WHERE user_id = $1 AND day_key = $2 AND daily_used < $3 RETURNING ' + QUOTA_COLUMNS,
            params: [userId, dayKey, config.dailyFree]
        },
        {
            sql: 'UPDATE match_quota SET bonus_balance = bonus_balance - 1, updated_at = NOW() '
                + 'WHERE user_id = $1 AND bonus_balance > 0 RETURNING ' + QUOTA_COLUMNS,
            params: [userId]
        }
    ];
    let updated = null;
    for (const attempt of attempts) {
        const result = await db.query(attempt.sql, attempt.params);
        if (result.rows.length > 0) {
            updated = result.rows[0];
            break;
        }
    }
    const quota = buildQuotaObject(updated || currentRow, config, at);
    return { consumed: Boolean(updated), quota };
};

// Credit a verified rewarded-ad bonus. Guarded again inside the UPDATE so a
// concurrent callback cannot push ads_today past the daily cap.
const creditAdReward = async (db, userId, options = {}) => {
    const config = resolveConfig(process.env);
    const at = options.now ? new Date(options.now) : new Date();
    const dayKey = dayKeyFor(at);
    const cap = toNonNegativeInt(options.dailyMax, config.adDailyMax);
    const amount = toNonNegativeInt(options.rewardAmount, config.adRewardMatches);
    const currentRow = await upsertQuotaRow(db, userId, dayKey, config.welcomeFree);
    if (currentRow.ads_today >= cap) {
        return { credited: false, reason: 'AD_LIMIT_REACHED', quota: buildQuotaObject(currentRow, config, at) };
    }
    const result = await db.query(
        'UPDATE match_quota SET bonus_balance = bonus_balance + $2, ads_today = ads_today + 1, updated_at = NOW() '
        + 'WHERE user_id = $1 AND ads_today < $3 RETURNING ' + QUOTA_COLUMNS,
        [userId, amount, cap]
    );
    const updated = result.rows[0] || null;
    if (!updated) {
        return { credited: false, reason: 'AD_LIMIT_REACHED', quota: buildQuotaObject(currentRow, config, at) };
    }
    return { credited: true, reason: null, quota: buildQuotaObject(updated, config, at) };
};

module.exports = {
    QUOTA_COLUMNS,
    TIMEZONE,
    buildQuotaObject,
    canStartSearch,
    consumeMatch,
    creditAdReward,
    dayKeyFor,
    getQuota,
    isEnabled,
    nextMidnightIso,
    resolveConfig,
    upsertQuotaRow
};
