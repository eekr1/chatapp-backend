const MATCH_SCOPE_VERSION = 'match-scope-v1';
const COUNTRY_POLICY_VERSION = 'match-country-v1';
const MATCH_SCOPES = Object.freeze({ GLOBAL: 'GLOBAL', COUNTRY: 'COUNTRY' });
const { displayCountry } = require('./countryPolicy');

const normalizeScope = (value) => value === MATCH_SCOPES.COUNTRY
    ? MATCH_SCOPES.COUNTRY
    : MATCH_SCOPES.GLOBAL;

const isIsoCountry = (value) => /^[A-Z]{2}$/.test(String(value || ''));

const queueKeyFor = ({ scope, countryCode = null }) => {
    const normalized = normalizeScope(scope);
    if (normalized === MATCH_SCOPES.GLOBAL) return 'match:global';
    if (!isIsoCountry(countryCode)) return null;
    return `match:country:${countryCode}`;
};

const getFallbackDelayMs = (env = process.env) => {
    const parsed = Number(env.MATCH_COUNTRY_FALLBACK_MS);
    if (!Number.isFinite(parsed)) return 30000;
    return Math.max(15000, Math.min(120000, Math.round(parsed)));
};

const resolveCanonicalMatchScope = async ({ pool, userId, requestedScope, locale = 'en' }) => {
    const scope = normalizeScope(requestedScope);
    if (scope === MATCH_SCOPES.GLOBAL) {
        return {
            ok: true,
            requestedScope: scope,
            effectiveScope: scope,
            country: null,
            queueKey: queueKeyFor({ scope }),
            countryPolicyVersion: COUNTRY_POLICY_VERSION
        };
    }

    const result = await pool.query(
        `SELECT country_code, status, confidence, policy_version, updated_at
           FROM user_match_country
          WHERE user_id = $1
          LIMIT 1`,
        [userId]
    );
    const row = result.rows[0] || null;
    if (!row || row.status === 'unavailable' || !isIsoCountry(row.country_code)) {
        return { ok: false, code: 'MATCH_COUNTRY_UNAVAILABLE', requestedScope: scope };
    }
    if (row.status !== 'eligible' || row.confidence !== 'policy_verified') {
        return { ok: false, code: 'MATCH_COUNTRY_STALE', requestedScope: scope };
    }
    const country = {
        code: row.country_code,
        displayName: String(displayCountry(row.country_code, locale) || row.country_code).slice(0, 80),
        version: String(row.policy_version || COUNTRY_POLICY_VERSION).slice(0, 80)
    };
    return {
        ok: true,
        requestedScope: scope,
        effectiveScope: scope,
        country,
        queueKey: queueKeyFor({ scope, countryCode: country.code }),
        countryPolicyVersion: country.version,
        countryUpdatedAt: row.updated_at || null
    };
};

const assertMatchScopeTopology = (runtimeConfig) => {
    if (runtimeConfig?.topology === 'shared-db') {
        const error = new Error('Scoped process-memory matchmaking requires REALTIME_TOPOLOGY=single.');
        error.code = 'MATCH_SCOPE_REQUIRES_SINGLE_INSTANCE';
        throw error;
    }
    return true;
};

const matchScopesCapability = (countryState = null) => ({
    version: MATCH_SCOPE_VERSION,
    supported: [MATCH_SCOPES.GLOBAL, MATCH_SCOPES.COUNTRY],
    countryAvailable: Boolean(countryState?.ok),
    country: countryState?.ok ? countryState.country : null,
    unavailableReason: countryState?.ok ? null : (countryState?.code || 'MATCH_COUNTRY_UNAVAILABLE')
});

module.exports = {
    COUNTRY_POLICY_VERSION,
    MATCH_SCOPES,
    MATCH_SCOPE_VERSION,
    assertMatchScopeTopology,
    getFallbackDelayMs,
    isIsoCountry,
    matchScopesCapability,
    normalizeScope,
    queueKeyFor,
    resolveCanonicalMatchScope
};
