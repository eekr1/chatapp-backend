const fs = require('fs');
const path = require('path');
const DEFAULT_PUSH_CHANNEL_ID = 'talkx_default_v2';

let admin = null;
let initAttempted = false;
let initErrorLogged = false;

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

const parseServiceAccountFile = (filePath) => {
    if (!filePath || typeof filePath !== 'string') return null;
    const resolved = path.isAbsolute(filePath)
        ? filePath
        : path.resolve(process.cwd(), filePath);
    if (!fs.existsSync(resolved)) return null;

    try {
        const raw = fs.readFileSync(resolved, 'utf8');
        return parseJson(raw, `Service account file (${resolved})`);
    } catch (e) {
        console.warn('Service account file read error:', e.message);
        return null;
    }
};

const parseServiceAccount = () => {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        const parsed = parseJson(process.env.FIREBASE_SERVICE_ACCOUNT_JSON, 'FIREBASE_SERVICE_ACCOUNT_JSON');
        if (parsed) return parsed;
    }
    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
        const json = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
        const parsed = parseJson(json, 'FIREBASE_SERVICE_ACCOUNT_BASE64');
        if (parsed) return parsed;
    }

    const fromEnvPath = parseServiceAccountFile(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
    if (fromEnvPath) return fromEnvPath;

    // Zero-config local fallback for development
    const localDefaultPath = path.resolve(__dirname, '..', 'firebase-service-account.json');
    const fromLocalDefault = parseServiceAccountFile(localDefaultPath);
    if (fromLocalDefault) return fromLocalDefault;

    if (!initErrorLogged) {
        initErrorLogged = true;
        console.warn('Push disabled: Firebase service account not configured.');
    }
    return null;
};

const ensureFirebase = () => {
    if (initAttempted) return !!admin;
    initAttempted = true;

    try {
        // Lazy require so backend can run even if firebase-admin is not installed yet.
        // eslint-disable-next-line global-require
        const firebaseAdmin = require('firebase-admin');
        const serviceAccount = parseServiceAccount();
        if (!serviceAccount) return false;

        if (!firebaseAdmin.apps.length) {
            firebaseAdmin.initializeApp({
                credential: firebaseAdmin.credential.cert(serviceAccount),
                projectId: serviceAccount.project_id || process.env.FIREBASE_PROJECT_ID
            });
        }
        admin = firebaseAdmin;
        return true;
    } catch (e) {
        console.warn('Push disabled:', e.message);
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

const sendPushToTokens = async (tokens, payload = {}) => {
    const cleanTokens = Array.from(new Set((tokens || []).filter(Boolean)));
    if (!cleanTokens.length) {
        return { enabled: false, tokenCount: 0, sentCount: 0, failureCount: 0, invalidTokens: [] };
    }

    if (!ensureFirebase()) {
        return { enabled: false, tokenCount: cleanTokens.length, sentCount: 0, failureCount: 0, invalidTokens: [] };
    }

    const message = {
        tokens: cleanTokens,
        notification: {
            title: payload.title || 'TalkX',
            body: payload.body || ''
        },
        data: normalizeData(payload.data || {}),
        android: {
            priority: 'high',
            notification: {
                sound: 'default',
                defaultSound: true,
                priority: 'PRIORITY_HIGH',
                channelId: payload.channelId || DEFAULT_PUSH_CHANNEL_ID
            }
        }
    };

    try {
        const response = await admin.messaging().sendEachForMulticast(message);
        const invalidTokens = [];
        response.responses.forEach((r, idx) => {
            if (r.success) return;
            const code = r.error && r.error.code;
            if (code && INVALID_TOKEN_CODES.has(code)) invalidTokens.push(cleanTokens[idx]);
        });

        return {
            enabled: true,
            tokenCount: cleanTokens.length,
            sentCount: response.successCount || 0,
            failureCount: response.failureCount || 0,
            invalidTokens
        };
    } catch (e) {
        console.error('sendPushToTokens error:', e.message);
        return {
            enabled: true,
            tokenCount: cleanTokens.length,
            sentCount: 0,
            failureCount: cleanTokens.length,
            invalidTokens: []
        };
    }
};

module.exports = {
    sendPushToTokens
};
