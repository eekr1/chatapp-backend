const packageJson = require('../package.json');

const clampInteger = (value, fallback, min, max) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.min(max, Math.trunc(parsed)));
};

const normalizeEnvironment = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    if (['development', 'test', 'staging', 'production'].includes(normalized)) return normalized;
    return 'unknown';
};

const normalizeCommitSha = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    return /^[a-f0-9]{7,64}$/.test(normalized) ? normalized : 'unknown';
};

const resolveReleaseIdentity = (env = process.env) => Object.freeze({
    service: 'talkx-backend',
    appVersion: String(packageJson.version || 'unknown'),
    commitSha: normalizeCommitSha(env.RENDER_GIT_COMMIT || env.COMMIT_SHA || env.GIT_COMMIT),
    environment: normalizeEnvironment(env.APP_ENV || env.NODE_ENV)
});

const resolveDatabaseRuntimeConfig = (env = process.env) => ({
    max: clampInteger(env.DB_POOL_MAX, env.NODE_ENV === 'production' ? 10 : 5, 1, 20),
    idleTimeoutMillis: clampInteger(env.DB_IDLE_TIMEOUT_MS, 30000, 1000, 120000),
    connectionTimeoutMillis: clampInteger(env.DB_CONNECT_TIMEOUT_MS, 5000, 500, 30000),
    query_timeout: clampInteger(env.DB_QUERY_TIMEOUT_MS, 10000, 500, 60000),
    statement_timeout: clampInteger(env.DB_STATEMENT_TIMEOUT_MS, 10000, 500, 60000),
    readinessTimeoutMs: clampInteger(env.DB_READINESS_TIMEOUT_MS, 4000, 500, 15000)
});

module.exports = {
    clampInteger,
    normalizeEnvironment,
    normalizeCommitSha,
    resolveReleaseIdentity,
    resolveDatabaseRuntimeConfig
};
