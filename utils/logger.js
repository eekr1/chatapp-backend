const crypto = require('crypto');
const nativeConsole = Object.freeze({
    info: console.info.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    log: console.log.bind(console)
});
const LOG_WINDOW_MS = 60 * 1000;
const LOG_MAX_PER_KEY = 200;
const logBuckets = new Map();

const ALLOWED_FIELDS = new Set([
    'timestamp', 'level', 'environment', 'release', 'component', 'operation',
    'result', 'durationMs', 'requestId', 'connectionId', 'eventId', 'errorCode',
    'actor', 'policy', 'retryAfterMs', 'status'
]);

const pseudonymize = (value) => {
    if (value === undefined || value === null || value === '') return null;
    return crypto.createHash('sha256')
        .update(`${process.env.LOG_PSEUDONYM_SALT || 'talkx-local'}:${String(value)}`)
        .digest('hex')
        .slice(0, 16);
};

const sanitizeFields = (fields = {}) => {
    const clean = {};
    for (const [key, value] of Object.entries(fields || {})) {
        if (!ALLOWED_FIELDS.has(key) || value === undefined) continue;
        if (key === 'actor') clean.actor = pseudonymize(value);
        else if (['durationMs', 'retryAfterMs', 'status'].includes(key)) clean[key] = Number.isFinite(Number(value)) ? Number(value) : null;
        else clean[key] = String(value).slice(0, 160);
    }
    return clean;
};

const createLogEntry = (level, component, operation, fields = {}) => ({
    timestamp: new Date().toISOString(),
    level,
    environment: String(process.env.NODE_ENV || 'development').slice(0, 40),
    release: String(process.env.RENDER_GIT_COMMIT || process.env.APP_RELEASE || 'local').slice(0, 80),
    component: String(component || 'app').slice(0, 80),
    operation: String(operation || 'unknown').slice(0, 120),
    ...sanitizeFields(fields)
});

const write = (level, component, operation, fields) => {
    const now = Date.now();
    const key = `${level}:${component}:${operation}`;
    let bucket = logBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) bucket = { count: 0, resetAt: now + LOG_WINDOW_MS };
    bucket.count += 1;
    logBuckets.set(key, bucket);
    if (bucket.count > LOG_MAX_PER_KEY) return null;
    if (logBuckets.size > 1000) {
        for (const [bucketKey, value] of logBuckets) {
            if (value.resetAt <= now || logBuckets.size > 1000) logBuckets.delete(bucketKey);
        }
    }
    const entry = createLogEntry(level, component, operation, fields);
    const line = JSON.stringify(entry);
    if (level === 'error') nativeConsole.error(line);
    else if (level === 'warn') nativeConsole.warn(line);
    else nativeConsole.info(line);
    return entry;
};

let safeConsoleInstalled = false;
const installSafeConsole = () => {
    if (safeConsoleInstalled) return;
    safeConsoleInstalled = true;
    const wrap = (level) => (...args) => {
        const error = args.find((item) => item instanceof Error);
        write(level, 'legacy', 'console', {
            result: error ? error.name : 'message',
            errorCode: typeof error?.code === 'string' ? error.code : undefined
        });
    };
    console.log = wrap('info');
    console.info = wrap('info');
    console.warn = wrap('warn');
    console.error = wrap('error');
};

module.exports = {
    createLogEntry,
    installSafeConsole,
    pseudonymize,
    sanitizeFields,
    info: (component, operation, fields) => write('info', component, operation, fields),
    warn: (component, operation, fields) => write('warn', component, operation, fields),
    error: (component, operation, fields) => write('error', component, operation, fields)
};
