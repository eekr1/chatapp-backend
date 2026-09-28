const { evaluateCountryCandidate } = require('./countryPolicy');
const { normalizeIp } = require('./clientIp');
const { resolveLocalCountry } = require('./localGeoCountry');

const refreshMs = (env = process.env) => Math.max(
    60 * 60 * 1000,
    Math.min(30 * 24 * 60 * 60 * 1000, Number(env.MATCH_COUNTRY_REFRESH_MS) || 7 * 24 * 60 * 60 * 1000)
);
const retryMs = (env = process.env) => Math.max(
    15 * 60 * 1000,
    Math.min(24 * 60 * 60 * 1000, Number(env.MATCH_COUNTRY_RETRY_MS) || 6 * 60 * 60 * 1000)
);
const batchSize = (env = process.env) => Math.max(1, Math.min(200, Number(env.MATCH_COUNTRY_BACKFILL_BATCH_SIZE) || 100));
const batchDelayMs = (env = process.env) => Math.max(1000, Math.min(60000, Number(env.MATCH_COUNTRY_BACKFILL_BATCH_DELAY_MS) || 5000));
const idleDelayMs = (env = process.env) => Math.max(60000, Math.min(24 * 60 * 60 * 1000, Number(env.MATCH_COUNTRY_BACKFILL_IDLE_MS) || 6 * 60 * 60 * 1000));

const loadCurrent = async (pool, userId) => {
    const result = await pool.query(
        `SELECT country_code, source, status, confidence, source_observed_at, resolved_at, updated_at, policy_version
           FROM user_match_country
          WHERE user_id = $1
          LIMIT 1`,
        [userId]
    );
    return result.rows[0] || null;
};

const loadLatestIp = async (pool, userId) => {
    const result = await pool.query(
        `SELECT ip
           FROM legal_acceptances
          WHERE user_id = $1
          ORDER BY accepted_at DESC, id DESC
          LIMIT 1`,
        [userId]
    );
    return normalizeIp(result.rows[0]?.ip);
};

const isFresh = (row, now, maxAgeMs) => {
    const timestamp = new Date(row?.resolved_at || row?.updated_at || 0).getTime();
    return Number.isFinite(timestamp) && now.getTime() - timestamp <= maxAgeMs;
};

const upsertCountry = async (pool, { userId, evaluated, source, now }) => {
    const result = await pool.query(
        `INSERT INTO user_match_country
          (user_id, country_code, source, status, confidence, source_observed_at, resolved_at, updated_at, policy_version)
         VALUES ($1, $2, $3, $4, $5, $6, $6, $6, $7)
         ON CONFLICT (user_id) DO UPDATE SET
           country_code = EXCLUDED.country_code,
           source = EXCLUDED.source,
           status = EXCLUDED.status,
           confidence = EXCLUDED.confidence,
           source_observed_at = EXCLUDED.source_observed_at,
           resolved_at = EXCLUDED.resolved_at,
           updated_at = EXCLUDED.updated_at,
           policy_version = EXCLUDED.policy_version
         RETURNING country_code, source, status, confidence, source_observed_at, resolved_at, updated_at, policy_version`,
        [userId, evaluated.countryCode, String(source || 'unknown').slice(0, 80), evaluated.status,
            evaluated.confidence, now, evaluated.policyVersion]
    );
    return result.rows[0];
};

const ensureUserMatchCountry = async ({
    pool,
    userId,
    ip = null,
    force = false,
    env = process.env,
    now = new Date(),
    resolver = resolveLocalCountry
}) => {
    if (!pool || !userId) throw new Error('Match country requires pool and userId.');
    const current = await loadCurrent(pool, userId);
    const sourceIp = normalizeIp(ip) || await loadLatestIp(pool, userId);
    const resolved = resolver(sourceIp);

    if (resolved?.ok) {
        const sameCountry = current?.status === 'eligible'
            && current?.confidence === 'policy_verified'
            && current?.country_code === resolved.countryCode;
        if (!force && sameCountry && isFresh(current, now, refreshMs(env))) {
            return { ...current, ok: true, refreshed: false };
        }
        const evaluated = evaluateCountryCandidate({
            country: resolved.countryCode,
            source: resolved.source,
            observedAt: now,
            now
        });
        const row = await upsertCountry(pool, { userId, evaluated, source: resolved.source, now });
        return { ...row, ok: true, refreshed: true };
    }

    // Private/missing IPs and lookup gaps must not erase a previously verified country.
    if (current?.status === 'eligible' && current?.confidence === 'policy_verified') {
        return { ...current, ok: true, refreshed: false, refreshDeferred: true };
    }
    if (!force && current && isFresh(current, now, retryMs(env))) {
        return { ...current, ok: false, refreshed: false };
    }

    const unavailable = evaluateCountryCandidate({
        country: null,
        source: resolved?.source || 'unresolved',
        observedAt: now,
        now
    });
    const row = await upsertCountry(pool, { userId, evaluated: unavailable, source: resolved?.source, now });
    return { ...row, ok: false, refreshed: true };
};

const loadBackfillCandidates = async (pool, { env = process.env, limit = batchSize(env) } = {}) => {
    const result = await pool.query(
        `SELECT u.id AS user_id, latest.ip
           FROM users u
           LEFT JOIN user_match_country mc ON mc.user_id = u.id
           LEFT JOIN LATERAL (
             SELECT la.ip
               FROM legal_acceptances la
              WHERE la.user_id = u.id
              ORDER BY la.accepted_at DESC, la.id DESC
              LIMIT 1
           ) latest ON TRUE
          WHERE u.status = 'active'
            AND (
              mc.user_id IS NULL
              OR (mc.status <> 'eligible' AND mc.updated_at < NOW() - ($1 * INTERVAL '1 millisecond'))
            )
          ORDER BY COALESCE(mc.updated_at, TO_TIMESTAMP(0)) ASC, u.created_at ASC
          LIMIT $2`,
        [retryMs(env), limit]
    );
    return result.rows;
};

const runMatchCountryBackfillBatch = async ({ pool, env = process.env, logger = console } = {}) => {
    const limit = batchSize(env);
    const candidates = await loadBackfillCandidates(pool, { env, limit });
    const counts = { selected: candidates.length, eligible: 0, unavailable: 0, failed: 0 };
    for (const candidate of candidates) {
        try {
            const result = await ensureUserMatchCountry({
                pool, userId: candidate.user_id, ip: candidate.ip, force: true, env
            });
            if (result?.status === 'eligible') counts.eligible += 1;
            else counts.unavailable += 1;
        } catch (error) {
            counts.failed += 1;
            logger.warn?.('match-country', 'backfill-user', { errorCode: error?.code || 'MATCH_COUNTRY_BACKFILL_FAILED' });
        }
    }
    return counts;
};

const startMatchCountryBackfill = ({ pool, env = process.env, logger = console } = {}) => {
    let stopped = false;
    let timer = null;
    const schedule = (delay) => {
        if (stopped) return;
        timer = setTimeout(run, delay);
        timer.unref?.();
    };
    const run = async () => {
        if (stopped) return;
        try {
            const counts = await runMatchCountryBackfillBatch({ pool, env, logger });
            if (counts.selected || counts.failed) {
                logger.info?.('match-country', 'backfill-batch', {
                    result: `selected=${counts.selected},eligible=${counts.eligible},unavailable=${counts.unavailable},failed=${counts.failed}`
                });
            }
            schedule(counts.selected >= batchSize(env) ? batchDelayMs(env) : idleDelayMs(env));
        } catch (error) {
            logger.warn?.('match-country', 'backfill-batch', { errorCode: error?.code || 'MATCH_COUNTRY_BACKFILL_BATCH_FAILED' });
            schedule(batchDelayMs(env));
        }
    };
    schedule(0);
    return () => {
        stopped = true;
        if (timer) clearTimeout(timer);
    };
};

module.exports = {
    ensureUserMatchCountry,
    loadBackfillCandidates,
    runMatchCountryBackfillBatch,
    startMatchCountryBackfill
};
