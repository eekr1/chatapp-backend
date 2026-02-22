const fs = require('fs');
const path = require('path');
const DEFAULT_PUSH_CHANNEL_ID = 'talkx_default_v2';
const MESSAGE_PUSH_CHANNEL_ID = 'talkx_messages_v2';
const ADMIN_PUSH_CHANNEL_ID = 'talkx_admin_v2';
const KNOWN_CHANNEL_IDS = new Set([
    DEFAULT_PUSH_CHANNEL_ID,
    MESSAGE_PUSH_CHANNEL_ID,
    ADMIN_PUSH_CHANNEL_ID
]);
const ERROR_SAMPLE_LIMIT = 5;

let admin = null;
const initState = {
    attempted: false,
    enabled: false,
    initError: null,
    projectIdUsed: null,
    credentialSource: null,
    expectedProjectId: null,
    initializedAt: null
};

const INVALID_TOKEN_CODES = new Set([
    'messaging/invalid-registration-token',
    'messaging/registration-token-not-registered'
]);

const parseJson = (raw, label) => {
    if (!raw) return null;
    try {
        return JSON.parse(raw);
    } catch (e) {
        console.warn(`${label} parse error:`, e.message);
        return null;
    }
};

const parseServiceAccountFile = (filePath, source) => {
    if (!filePath || typeof filePath !== 'string') return null;
    const resolved = path.isAbsolute(filePath)
        ? filePath
        : path.resolve(process.cwd(), filePath);
    if (!fs.existsSync(resolved)) return null;

    try {
        const raw = fs.readFileSync(resolved, 'utf8');
        const parsed = parseJson(raw, `Service account file (${resolved})`);
        if (!parsed) return null;
        return { serviceAccount: parsed, source: source || `path:${resolved}` };
    } catch (e) {
        console.warn('Service account file read error:', e.message);
        return null;
    }
};

const normalizePrivateKey = (privateKey) => String(privateKey || '').replace(/\\n/g, '\n');

const validateServiceAccount = (serviceAccount) => {
    if (!serviceAccount || typeof serviceAccount !== 'object') {
        return 'Firebase service account is empty.';
    }
    const required = ['project_id', 'client_email', 'private_key'];
    for (const key of required) {
        if (!serviceAccount[key] || typeof serviceAccount[key] !== 'string') {
            return `Firebase service account missing field: ${key}`;
        }
    }
    return null;
};

const parseServiceAccount = () => {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        const parsed = parseJson(process.env.FIREBASE_SERVICE_ACCOUNT_JSON, 'FIREBASE_SERVICE_ACCOUNT_JSON');
        if (parsed) return { serviceAccount: parsed, source: 'json' };
    }
    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
        const json = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
        const parsed = parseJson(json, 'FIREBASE_SERVICE_ACCOUNT_BASE64');
        if (parsed) return { serviceAccount: parsed, source: 'base64' };
    }

    const fromEnvPath = parseServiceAccountFile(process.env.FIREBASE_SERVICE_ACCOUNT_PATH, 'path_env');
    if (fromEnvPath) return fromEnvPath;

    // Zero-config local fallback for development
    const localDefaultPath = path.resolve(__dirname, '..', 'firebase-service-account.json');
    const fromLocalDefault = parseServiceAccountFile(localDefaultPath, 'path_local_default');
    if (fromLocalDefault) return fromLocalDefault;

    return null;
};

const setInitFailure = (message, fallbackProjectId = null) => {
    initState.enabled = false;
    initState.initError = String(message || 'Firebase init failed.');
    initState.projectIdUsed = fallbackProjectId || null;
    initState.initializedAt = new Date().toISOString();
};

const ensureFirebase = () => {
    if (initState.attempted) return initState.enabled;
    initState.attempted = true;
    initState.expectedProjectId = (process.env.FIREBASE_EXPECTED_PROJECT_ID || '').trim() || null;

    try {
        // Lazy require so backend can run even if firebase-admin is not installed yet.
        // eslint-disable-next-line global-require
        const firebaseAdmin = require('firebase-admin');
        const parsed = parseServiceAccount();
        if (!parsed || !parsed.serviceAccount) {
            setInitFailure('Firebase service account is not configured.');
            console.error('[push] Firebase init failed: service account missing.');
            return false;
        }

        const serviceAccount = {
            ...parsed.serviceAccount,
            private_key: normalizePrivateKey(parsed.serviceAccount.private_key)
        };
        const validationError = validateServiceAccount(serviceAccount);
        if (validationError) {
            setInitFailure(validationError, serviceAccount.project_id || null);
            console.error(`[push] Firebase init failed: ${validationError}`);
            return false;
        }

        const projectId = serviceAccount.project_id || process.env.FIREBASE_PROJECT_ID || null;
        if (initState.expectedProjectId && !projectId) {
            setInitFailure(
                `FIREBASE_EXPECTED_PROJECT_ID is set (${initState.expectedProjectId}) but credential project_id is missing.`
            );
            initState.credentialSource = parsed.source;
            console.error(
                `[push] Firebase init failed: expected project is set but project_id is missing in credential. source=${parsed.source}`
            );
            return false;
        }
        if (initState.expectedProjectId && projectId && initState.expectedProjectId !== projectId) {
            setInitFailure(
                `FIREBASE_EXPECTED_PROJECT_ID mismatch (expected=${initState.expectedProjectId}, actual=${projectId}).`,
                projectId
            );
            initState.credentialSource = parsed.source;
            console.error(
                `[push] Firebase init failed: expected project mismatch. expected=${initState.expectedProjectId}, actual=${projectId}, source=${parsed.source}`
            );
            return false;
        }
        if (!firebaseAdmin.apps.length) {
            firebaseAdmin.initializeApp({
                credential: firebaseAdmin.credential.cert(serviceAccount),
                projectId
            });
        }
        admin = firebaseAdmin;
        initState.enabled = true;
        initState.initError = null;
        initState.projectIdUsed = projectId;
        initState.credentialSource = parsed.source;
        initState.initializedAt = new Date().toISOString();
        console.info(
            `[push] Firebase init success: project_id=${projectId || '-'} source=${parsed.source}`
        );
        return initState.enabled;
    } catch (e) {
        const code = e && e.code ? e.code : 'unknown';
        const message = e && e.message ? e.message : String(e);
        setInitFailure(`${code}: ${message}`);
        console.error(`[push] Firebase init failed: ${code}: ${message}`);
        return false;
    }
};

const normalizeData = (data = {}) => {
    const out = {};
    Object.entries(data).forEach(([k, v]) => {
        if (v === undefined || v === null) return;
        out[k] = String(v);
    });
    return out;
};

const toPositiveInt = (value, fallback) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
    return Math.round(parsed);
};

const resolveChannelId = (channelId, fallback = DEFAULT_PUSH_CHANNEL_ID) => {
    const requested = String(channelId || '').trim();
    if (!requested) return fallback;
    return KNOWN_CHANNEL_IDS.has(requested) ? requested : DEFAULT_PUSH_CHANNEL_ID;
};

const resolvePushOptions = (payload = {}) => {
    const type = String(payload?.data?.type || '').trim();
    const defaultForAdmin = type === 'admin_notice';
    const defaultTtlSeconds = defaultForAdmin ? 86400 : 3600;
    const defaultCollapseKey = defaultForAdmin ? 'talkx_admin_notice' : 'talkx_direct_message';
    const defaultChannelId = defaultForAdmin ? ADMIN_PUSH_CHANNEL_ID : MESSAGE_PUSH_CHANNEL_ID;

    const ttlSeconds = toPositiveInt(payload.ttlSeconds, defaultTtlSeconds);
    const collapseKey = String(payload.collapseKey || defaultCollapseKey).trim() || defaultCollapseKey;
    const channelId = resolveChannelId(payload.channelId, defaultChannelId);

    return { ttlMs: ttlSeconds * 1000, collapseKey, channelId };
};

const summarizeError = (err) => {
    const code = (err && err.code) ? String(err.code) : 'unknown';
    const message = (err && err.message) ? String(err.message) : 'Unknown push error';
    return { code, message };
};

const buildDisabledResult = (tokenCount = 0) => ({
    enabled: false,
    tokenCount,
    sentCount: 0,
    failureCount: 0,
    invalidTokens: [],
    errorSummary: {},
    errorSamples: [],
    firebaseEnabled: initState.enabled,
    initError: initState.initError,
    projectIdUsed: initState.projectIdUsed,
    credentialSource: initState.credentialSource
});

const sendPushToTokens = async (tokens, payload = {}) => {
    const cleanTokens = Array.from(new Set((tokens || []).filter(Boolean)));
    if (!cleanTokens.length) {
        return buildDisabledResult(0);
    }

    if (!ensureFirebase()) {
        return buildDisabledResult(cleanTokens.length);
    }

    const pushOptions = resolvePushOptions(payload);
    const message = {
        tokens: cleanTokens,
        notification: {
            title: payload.title || 'TalkX',
            body: payload.body || ''
        },
        data: normalizeData(payload.data || {}),
        android: {
            priority: 'high',
            ttl: pushOptions.ttlMs,
            collapseKey: pushOptions.collapseKey,
            notification: {
                sound: 'default',
                defaultSound: true,
                // Firebase Admin AndroidNotification priority expects 'high', not 'PRIORITY_HIGH'.
                priority: 'high',
                channelId: pushOptions.channelId
            }
        }
    };

    try {
        const response = await admin.messaging().sendEachForMulticast(message);
        const invalidTokens = [];
        const errorSummary = {};
        const errorSamples = [];

        response.responses.forEach((r, idx) => {
            if (r.success) return;
            const { code, message: errorMessage } = summarizeError(r.error);
            errorSummary[code] = (errorSummary[code] || 0) + 1;
            if (errorSamples.length < ERROR_SAMPLE_LIMIT) {
                errorSamples.push({
                    code,
                    message: errorMessage,
                    tokenSuffix: String(cleanTokens[idx] || '').slice(-8)
                });
            }
            if (code && INVALID_TOKEN_CODES.has(code)) invalidTokens.push(cleanTokens[idx]);
        });

        return {
            enabled: true,
            tokenCount: cleanTokens.length,
            sentCount: response.successCount || 0,
            failureCount: response.failureCount || 0,
            invalidTokens,
            errorSummary,
            errorSamples,
            firebaseEnabled: initState.enabled,
            initError: initState.initError,
            projectIdUsed: initState.projectIdUsed,
            credentialSource: initState.credentialSource
        };
    } catch (e) {
        const { code, message: errorMessage } = summarizeError(e);
        console.error('sendPushToTokens error:', code, errorMessage);
        return {
            enabled: true,
            tokenCount: cleanTokens.length,
            sentCount: 0,
            failureCount: cleanTokens.length,
            invalidTokens: [],
            errorSummary: { [code]: cleanTokens.length },
            errorSamples: [{ code, message: errorMessage }],
            firebaseEnabled: initState.enabled,
            initError: initState.initError,
            projectIdUsed: initState.projectIdUsed,
            credentialSource: initState.credentialSource
        };
    }
};

const getPushDiagnostics = () => {
    if (!initState.attempted) ensureFirebase();
    return {
        enabled: initState.enabled,
        initError: initState.initError,
        projectId: initState.projectIdUsed,
        credentialSource: initState.credentialSource,
        expectedProjectId: initState.expectedProjectId,
        initializedAt: initState.initializedAt
    };
};

module.exports = {
    sendPushToTokens,
    getPushDiagnostics
};
