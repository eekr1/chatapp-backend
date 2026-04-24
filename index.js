require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { WebSocketServer, WebSocket } = require('ws');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
const { pool, ensureTables } = require('./db');
const { validateUsername } = require('./moderation');
const adminRoutes = require('./admin');
const authRoutes = require('./routes/auth');
const profileRoutes = require('./routes/profile');
const friendsRoutes = require('./routes/friends');
const pushRoutes = require('./routes/push');
const supportRoutes = require('./routes/support');
const { sendPushToTokens, getPushDiagnostics } = require('./utils/push');
const { shouldDebouncePush } = require('./utils/pushDebounce');
const { fetchLegalSettings } = require('./utils/legalContent');
const { normalizeLang, resolveRequestLang, resolveLangFromHeaders, t } = require('./utils/i18n');

// Global State (Only Transients)
// Connected clients mapping: clientId -> { ws, dbUserId, deviceId, isShadowBanned, nickname }
const activeClients = new Map();

const app = express();
const port = process.env.PORT || 3000;
const REQUEST_TELEMETRY_SAMPLE_RATE = 0.2;
const REQUEST_TELEMETRY_SLOW_MS = 1500;
const REQUEST_TELEMETRY_EVENTS_RETENTION_DAYS = 7;
const REQUEST_TELEMETRY_METRICS_RETENTION_DAYS = 30;
const REQUEST_TELEMETRY_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const REQUEST_TELEMETRY_CLEANUP_CHANCE = 0.02;
const REQUEST_TELEMETRY_STATIC_FILE_RE = /\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|otf|mp4|webm|ogg)$/i;
const UUID_SEGMENT_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/ig;
const NUMERIC_SEGMENT_RE = /\/\d+(?=\/|$)/g;
const requestTelemetryCleanupState = { running: false, lastRunAt: 0 };

const toTelemetryPath = (rawUrl = '/') => {
    const raw = String(rawUrl || '/').split('?')[0].trim() || '/';
    return raw.startsWith('/') ? raw : `/${raw}`;
};

const normalizeTelemetryRoute = (value = '/') => {
    let route = toTelemetryPath(value)
        .replace(UUID_SEGMENT_RE, ':uuid')
        .replace(NUMERIC_SEGMENT_RE, '/:id')
        .replace(/\/{2,}/g, '/');
    if (route.length > 180) route = route.slice(0, 180);
    return route || '/';
};

const isTelemetryCandidatePath = (pathName = '/') => (
    pathName.startsWith('/api')
    || pathName.startsWith('/auth')
    || pathName.startsWith('/friends')
    || pathName.startsWith('/support')
);

const isTelemetryExcludedPath = (pathName = '/') => {
    if (pathName === '/health') return true;
    if (pathName === '/admin/stream') return true;
    if (pathName.startsWith('/admin/assets/')) return true;
    if (pathName.startsWith('/assets/')) return true;
    if (pathName.startsWith('/sounds/')) return true;
    if (REQUEST_TELEMETRY_STATIC_FILE_RE.test(pathName)) return true;
    return false;
};

const resolveTelemetryRouteTag = (req, fallbackPath) => {
    const routePath = typeof req?.route?.path === 'string' ? req.route.path : '';
    if (routePath) {
        const base = typeof req?.baseUrl === 'string' ? req.baseUrl : '';
        return normalizeTelemetryRoute(`${base}${routePath}`);
    }
    return normalizeTelemetryRoute(fallbackPath);
};

const maybeCleanupRequestTelemetry = () => {
    const now = Date.now();
    if (requestTelemetryCleanupState.running) return;
    if (now - requestTelemetryCleanupState.lastRunAt < REQUEST_TELEMETRY_CLEANUP_INTERVAL_MS) return;
    if (Math.random() > REQUEST_TELEMETRY_CLEANUP_CHANCE) return;

    requestTelemetryCleanupState.running = true;
    requestTelemetryCleanupState.lastRunAt = now;

    Promise.all([
        pool.query(
            `DELETE FROM http_request_events
             WHERE created_at < NOW() - ($1::text || ' days')::interval`,
            [REQUEST_TELEMETRY_EVENTS_RETENTION_DAYS]
        ),
        pool.query(
            `DELETE FROM http_request_metrics_minute
             WHERE bucket_minute < NOW() - ($1::text || ' days')::interval`,
            [REQUEST_TELEMETRY_METRICS_RETENTION_DAYS]
        )
    ])
        .catch((e) => {
            console.warn('request telemetry cleanup failed:', e?.message || e);
        })
        .finally(() => {
            requestTelemetryCleanupState.running = false;
        });
};

// Middleware to expose online status
app.use((req, res, next) => {
    req.isUserOnline = (userId) => {
        for (const [clientId, client] of activeClients) {
            if (client.dbUserId === userId) return true;
        }
        return false;
    };
    req.notifyUser = (userId, data) => {
        for (const [clientId, client] of activeClients) {
            if (client.dbUserId === userId && client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify(data));
            }
        }
    };
    next();
});

const defaultAllowedOrigins = [
    "https://talkx.chat",
    "https://www.talkx.chat",
    "http://localhost",
    "https://localhost",
    "http://localhost:3000",
    "capacitor://localhost"
];
const envAllowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
const allowedOrigins = new Set([...defaultAllowedOrigins, ...envAllowedOrigins]);

const baseCorsOptions = {
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    credentials: true
};

const isSameHostOrigin = (origin, req) => {
    try {
        const originUrl = new URL(origin);
        return originUrl.host === req.get('host');
    } catch {
        return false;
    }
};

app.use(express.json());

app.use(cors((req, callback) => {
    const origin = req.get('Origin');

    // Origin yoksa (native app, server-to-server) izin ver.
    if (!origin) {
        return callback(null, { ...baseCorsOptions, origin: true });
    }

    // Explicit allow-list (sabit + env)
    if (allowedOrigins.has(origin)) {
        return callback(null, { ...baseCorsOptions, origin: true });
    }

    // Admin panelindeki istekleri ayni hosttan geldigi surece bloklama.
    if (req.path.startsWith('/admin') && isSameHostOrigin(origin, req)) {
        return callback(null, { ...baseCorsOptions, origin: true });
    }

    console.warn('CORS blocked for origin:', origin, 'path:', req.path);
    return callback(null, { ...baseCorsOptions, origin: false });
}));

app.use((req, res, next) => {
    if (req.method === 'OPTIONS') return next();

    const startedAt = Date.now();
    const requestPath = toTelemetryPath(req.originalUrl || req.url || req.path || '/');
    if (!isTelemetryCandidatePath(requestPath) || isTelemetryExcludedPath(requestPath)) {
        return next();
    }

    const requestId = String(req.get('x-request-id') || '').trim() || uuidv4();
    res.on('finish', () => {
        const finishedAt = Date.now();
        const durationMs = Math.max(0, finishedAt - startedAt);
        const status = Number(res.statusCode) || 0;
        const statusClass = `${Math.floor(Math.max(100, status) / 100)}xx`;
        const isError = status >= 500;
        const isSlow = durationMs >= REQUEST_TELEMETRY_SLOW_MS;
        const sampleReason = isError ? 'error' : (isSlow ? 'slow' : 'sampled');
        const shouldStoreEvent = isError || isSlow || Math.random() < REQUEST_TELEMETRY_SAMPLE_RATE;
        const routeTag = resolveTelemetryRouteTag(req, requestPath);
        const responseSizeRaw = Number.parseInt(String(res.getHeader('content-length') || ''), 10);
        const responseSizeBytes = Number.isFinite(responseSizeRaw) && responseSizeRaw >= 0
            ? responseSizeRaw
            : null;

        pool.query(
            `INSERT INTO http_request_metrics_minute
              (bucket_minute, method, route, status_class, req_count, error_count, slow_count, total_duration_ms, updated_at)
             VALUES (date_trunc('minute', NOW()), $1, $2, $3, 1, $4, $5, $6, NOW())
             ON CONFLICT (bucket_minute, method, route, status_class)
             DO UPDATE SET
               req_count = http_request_metrics_minute.req_count + 1,
               error_count = http_request_metrics_minute.error_count + EXCLUDED.error_count,
               slow_count = http_request_metrics_minute.slow_count + EXCLUDED.slow_count,
               total_duration_ms = http_request_metrics_minute.total_duration_ms + EXCLUDED.total_duration_ms,
               updated_at = NOW()`,
            [
                req.method || 'GET',
                routeTag,
                statusClass,
                isError ? 1 : 0,
                isSlow ? 1 : 0,
                durationMs
            ]
        ).catch((e) => {
            console.warn('request telemetry metrics insert failed:', e?.message || e);
        });

        if (shouldStoreEvent) {
            pool.query(
                `INSERT INTO http_request_events
                  (method, route, status, duration_ms, response_size_bytes, request_id, sample_reason, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
                [
                    req.method || 'GET',
                    routeTag,
                    status,
                    durationMs,
                    responseSizeBytes,
                    requestId,
                    sampleReason
                ]
            ).catch((e) => {
                console.warn('request telemetry event insert failed:', e?.message || e);
            });
        }

        maybeCleanupRequestTelemetry();
    });

    next();
});


// Security: Rate Limiters
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 50, // 50 requests per IP
    handler: (req, res) => {
        const lang = resolveRequestLang(req);
        return res.status(429).json({
            error: t(lang, 'errors.RATE_LIMIT', {}, 'Too many attempts. Please wait.'),
            code: 'RATE_LIMIT'
        });
    }
});

const apiLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 300, // 300 requests per IP
    handler: (req, res) => {
        const lang = resolveRequestLang(req);
        return res.status(429).json({
            error: t(lang, 'errors.RATE_LIMIT', {}, 'Too many attempts. Please wait.'),
            code: 'RATE_LIMIT'
        });
    }
});

app.use('/auth', authLimiter);
app.use('/api', apiLimiter);
app.use('/friends', apiLimiter);

app.use('/admin', adminRoutes);
app.use('/auth', authRoutes);
app.use('/api', profileRoutes); // Mounting profile under /api since it's logical API (e.g. /api/me)
app.use('/api/push', pushRoutes);
app.use('/friends', friendsRoutes);
app.use('/support', supportRoutes);
app.get('/api/legal', async (req, res) => {
    try {
        const { item, updatedAt } = await fetchLegalSettings(pool);
        res.json({ ...item, updatedAt });
    } catch (e) {
        const lang = resolveRequestLang(req);
        res.status(500).json({
            error: t(lang, 'errors.SERVER_ERROR', {}, 'Server error.'),
            code: 'SERVER_ERROR'
        });
    }
});

app.get('/health', (req, res) => {
    res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

/**
 * Global State (Only Transients)
 * DB handles presistence. Memory only for active connections.
 * 
 * V6 UPDATE: 'username' is now fetched from DB for connected users if available.
 */
let waitingQueue = []; // [{ clientId, ws, nickname, dbUserId }]
const rooms = new Map(); // roomId -> { users: [...], sockets: {...}, conversationId: uuid }
const userRoomMap = new Map(); // clientId (socket uuid) -> roomId
const pendingMatches = new Map(); // matchId -> { id, users, autoAcceptAt, timeoutMs, timer, finalized }
const userPendingMatchMap = new Map(); // clientId -> matchId
const pairRematchCooldowns = new Map(); // pairKey -> expiresAt


// Config
const RATE_LIMIT_WINDOW = 1000;
const RATE_LIMIT_MAX = 5;
const REPORT_TTL = 5 * 60 * 1000;
const HEARTBEAT_INTERVAL = 30000;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024; // 2MB
const EPHEMERAL_MEDIA_TTL_DAYS = 7;
const MATCH_CONFIRM_TIMEOUT_MS = (() => {
    const parsed = Number(process.env.MATCH_CONFIRM_TIMEOUT_MS);
    if (!Number.isFinite(parsed)) return 8000;
    return Math.max(5000, Math.min(10000, Math.round(parsed)));
})();
const MATCH_REMATCH_COOLDOWN_MS = (() => {
    const parsed = Number(process.env.MATCH_REMATCH_COOLDOWN_MS);
    const min = 5 * 60 * 1000;
    const max = 10 * 60 * 1000;
    if (!Number.isFinite(parsed)) return 10 * 60 * 1000;
    return Math.max(min, Math.min(max, Math.round(parsed)));
})();
const PUSH_CHANNEL_IDS = {
    messages: 'talkx_messages_v3',
    admin: 'talkx_admin_v3',
    default: 'talkx_default_v3'
};

// Rate Limit Map (Memory is fine for rate limit)
const rateLimitMap = new Map();

// Recent Rooms for Report fallback (Memory cache)
const recentRooms = new Map();

// Helpers
const sendJson = (ws, data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
};

const resolveWsLang = (ws) => {
    const fromClient = activeClients.get(ws.clientId)?.lang || null;
    const fromSocket = ws.prefLang || null;
    return normalizeLang(fromClient || fromSocket, 'en');
};

const resolveUserLang = async (userId, fallback = 'en') => {
    try {
        if (!userId) return normalizeLang(fallback, 'en');
        const online = [...activeClients.values()].find((client) => client.dbUserId === userId);
        if (online?.lang) return normalizeLang(online.lang, fallback);
        const res = await pool.query(
            'SELECT locale FROM profiles WHERE user_id = $1 LIMIT 1',
            [userId]
        );
        const locale = res.rows[0]?.locale;
        return normalizeLang(locale, fallback);
    } catch (e) {
        console.warn('resolveUserLang fallback:', e?.message || e);
        return normalizeLang(fallback, 'en');
    }
};

const sendError = (ws, code, message = null, extra = {}) => {
    const lang = resolveWsLang(ws);
    const fallback = t(lang, 'ws.SERVER_ERROR', {}, 'Server error.');
    const resolvedMessage = message || t(lang, `ws.${code}`, {}, fallback);
    sendJson(ws, { type: 'error', code, message: resolvedMessage, ...extra });
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUuid = (value) => typeof value === 'string' && UUID_RE.test(value);
const toText = (value, fallback = '') => (typeof value === 'string' ? value : fallback);
const toClientMsgId = (value) => {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    if (!trimmed || trimmed.length > 120) return null;
    return trimmed;
};
const clampDuration = (value, fallback = 10000) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(3000, Math.min(60000, Math.round(parsed)));
};
const composeAdminPushBody = (noticeTitle, body) => {
    const cleanNoticeTitle = toText(noticeTitle, '').trim();
    const cleanBody = toText(body, '').trim();
    if (cleanNoticeTitle && cleanBody) return `${cleanNoticeTitle}: ${cleanBody}`;
    return cleanBody || cleanNoticeTitle || '';
};

const estimateBase64Bytes = (b64) => {
    if (typeof b64 !== 'string') return 0;
    const len = b64.length;
    const padding = b64.endsWith('==') ? 2 : (b64.endsWith('=') ? 1 : 0);
    return Math.max(0, Math.floor((len * 3) / 4) - padding);
};

const disableInvalidPushTokens = async (tokens) => {
    if (!tokens || !tokens.length) return;
    try {
        await pool.query(
            'UPDATE push_devices SET is_active = FALSE, updated_at = NOW() WHERE push_token = ANY($1::text[])',
            [tokens]
        );
    } catch (e) {
        console.error('Failed to disable invalid push tokens:', e.message);
    }
};

const buildPushLogMeta = (source, pushResult = {}, extra = {}) => ({
    source,
    firebaseEnabled: Boolean(
        pushResult.firebaseEnabled !== undefined ? pushResult.firebaseEnabled : pushResult.enabled
    ),
    projectIdUsed: pushResult.projectIdUsed || null,
    errorSummary: pushResult.errorSummary || {},
    errorSamples: Array.isArray(pushResult.errorSamples) ? pushResult.errorSamples.slice(0, 5) : [],
    ...extra
});

const logPushDelivery = async ({
    deliveryId = null,
    eventType = 'unknown',
    targetUserId = null,
    tokenCount = 0,
    sentCount = 0,
    failureCount = 0,
    invalidTokenCount = 0,
    channelId = null,
    meta = {}
}) => {
    try {
        await pool.query(
            `INSERT INTO push_delivery_logs
              (delivery_id, event_type, target_user_id, token_count, sent_count, failure_count, invalid_token_count, channel_id, meta)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
            [
                deliveryId && isUuid(deliveryId) ? deliveryId : null,
                eventType,
                targetUserId && isUuid(targetUserId) ? targetUserId : null,
                Number(tokenCount) || 0,
                Number(sentCount) || 0,
                Number(failureCount) || 0,
                Number(invalidTokenCount) || 0,
                channelId || null,
                JSON.stringify(meta || {})
            ]
        );
    } catch (e) {
        console.error('push delivery log insert failed:', e.message);
    }
};

const logDebouncedPush = ({
    deliveryId,
    eventType,
    targetUserId,
    conversationId,
    channelId,
    debounce
}) => {
    const meta = {
        source: 'push_debounce',
        reason: 'conversation_throttle',
        conversationId: conversationId || null,
        debounceKey: debounce?.key || null,
        debounceWindowMs: debounce?.windowMs || null,
        retryAfterMs: debounce?.waitMs || null
    };
    logPushDelivery({
        deliveryId,
        eventType,
        targetUserId,
        tokenCount: 0,
        sentCount: 0,
        failureCount: 0,
        invalidTokenCount: 0,
        channelId: channelId || PUSH_CHANNEL_IDS.messages,
        meta
    }).catch((e) => console.error('debounced push log insert failed:', e.message));
};

const sendPushToUser = async (userId, payload = {}, options = {}) => {
    if (!userId) {
        return {
            enabled: false,
            tokenCount: 0,
            sentCount: 0,
            failureCount: 0,
            invalidTokens: [],
            errorSummary: {},
            errorSamples: []
        };
    }
    const deliveryId = (payload.data && payload.data.deliveryId) || options.deliveryId || uuidv4();
    const eventType = options.eventType || (payload.data && payload.data.type) || 'unknown';
    const channelId = payload.channelId || null;
    const pushPayload = {
        ...payload,
        data: {
            ...(payload.data || {}),
            deliveryId: String(deliveryId)
        }
    };

    try {
        const tokenRes = await pool.query(
            `SELECT DISTINCT ON (COALESCE(NULLIF(device_id, ''), ('user:' || user_id::text))) push_token
             FROM push_devices
             WHERE user_id = $1 AND is_active = TRUE
             ORDER BY COALESCE(NULLIF(device_id, ''), ('user:' || user_id::text)), updated_at DESC`,
            [userId]
        );
        const tokens = tokenRes.rows.map(r => r.push_token).filter(Boolean);
        const result = await sendPushToTokens(tokens, pushPayload);
        if (result.invalidTokens && result.invalidTokens.length) {
            disableInvalidPushTokens(result.invalidTokens);
        }
        await logPushDelivery({
            deliveryId,
            eventType,
            targetUserId: userId,
            tokenCount: result.tokenCount || 0,
            sentCount: result.sentCount || 0,
            failureCount: result.failureCount || 0,
            invalidTokenCount: (result.invalidTokens || []).length,
            channelId,
            meta: buildPushLogMeta('sendPushToUser', result)
        });
        return { ...result, deliveryId };
    } catch (e) {
        console.error('sendPushToUser query error:', e.message);
        const diagnostics = getPushDiagnostics();
        const fallbackResult = {
            enabled: false,
            firebaseEnabled: diagnostics.enabled,
            projectIdUsed: diagnostics.projectId || null,
            errorSummary: { db_query_error: 1 },
            errorSamples: [{ code: 'db_query_error', message: e.message }]
        };
        await logPushDelivery({
            deliveryId,
            eventType,
            targetUserId: userId,
            tokenCount: 0,
            sentCount: 0,
            failureCount: 1,
            invalidTokenCount: 0,
            channelId,
            meta: buildPushLogMeta('sendPushToUser', fallbackResult, { error: e.message })
        });
        return {
            enabled: false,
            tokenCount: 0,
            sentCount: 0,
            failureCount: 0,
            invalidTokens: [],
            errorSummary: fallbackResult.errorSummary,
            errorSamples: fallbackResult.errorSamples,
            firebaseEnabled: fallbackResult.firebaseEnabled,
            projectIdUsed: fallbackResult.projectIdUsed,
            initError: diagnostics.initError || null
        };
    }
};

adminRoutes.sendSystemNotice = async ({ title, body, durationMs, target = 'all' }) => {
    const noticeTitle = toText(title, 'Duyuru').trim().slice(0, 80) || 'Duyuru';
    const cleanBody = toText(body, '').trim().slice(0, 300);
    const senderTitle = 'TalkX';
    const normalizedTarget = ['all', 'online', 'mobile'].includes(String(target)) ? String(target) : 'all';
    const ttlMs = clampDuration(durationMs, 10000);
    const deliveryId = uuidv4();

    let wsDelivered = 0;
    if (normalizedTarget === 'all' || normalizedTarget === 'online') {
        for (const [, client] of activeClients) {
            if (!client || client.ws.readyState !== WebSocket.OPEN) continue;
            sendJson(client.ws, {
                type: 'admin_notice',
                title: senderTitle,
                noticeTitle,
                body: cleanBody,
                durationMs: ttlMs,
                deliveryId
            });
            wsDelivered++;
        }
    }

    let pushResult = {
        enabled: false,
        tokenCount: 0,
        sentCount: 0,
        failureCount: 0,
        invalidTokens: [],
        errorSummary: {},
        errorSamples: []
    };
    if (normalizedTarget === 'all' || normalizedTarget === 'mobile') {
        try {
            const tokenRes = await pool.query(
                `SELECT DISTINCT ON ((COALESCE(user_id::text, '') || ':' || COALESCE(NULLIF(device_id, ''), 'no-device'))) push_token
                 FROM push_devices
                 WHERE is_active = TRUE
                 ORDER BY (COALESCE(user_id::text, '') || ':' || COALESCE(NULLIF(device_id, ''), 'no-device')), updated_at DESC`
            );
            const tokens = tokenRes.rows.map(r => r.push_token).filter(Boolean);
            pushResult = await sendPushToTokens(tokens, {
                title: senderTitle,
                body: composeAdminPushBody(noticeTitle, cleanBody),
                ttlSeconds: 86400,
                collapseKey: 'talkx_admin_notice',
                channelId: PUSH_CHANNEL_IDS.admin,
                data: {
                    type: 'admin_notice',
                    title: senderTitle,
                    noticeTitle,
                    body: cleanBody,
                    durationMs: String(ttlMs),
                    deliveryId,
                    channelId: PUSH_CHANNEL_IDS.admin
                }
            });
            if (pushResult.invalidTokens && pushResult.invalidTokens.length) {
                disableInvalidPushTokens(pushResult.invalidTokens);
            }
        } catch (e) {
            console.error('admin notice push error:', e.message);
            const diagnostics = getPushDiagnostics();
            pushResult = {
                ...pushResult,
                firebaseEnabled: diagnostics.enabled,
                projectIdUsed: diagnostics.projectId || null,
                errorSummary: { admin_notice_push_error: 1 },
                errorSamples: [{ code: 'admin_notice_push_error', message: e.message }]
            };
        }
    }

    await logPushDelivery({
        deliveryId,
        eventType: 'admin_notice',
        targetUserId: null,
        tokenCount: pushResult.tokenCount || 0,
        sentCount: pushResult.sentCount || 0,
        failureCount: pushResult.failureCount || 0,
        invalidTokenCount: (pushResult.invalidTokens || []).length,
        channelId: PUSH_CHANNEL_IDS.admin,
        meta: buildPushLogMeta('admin_notice', pushResult, { target: normalizedTarget, wsDelivered })
    });

    return {
        deliveryId,
        wsDelivered,
        push: {
            enabled: !!pushResult.enabled,
            tokenCount: pushResult.tokenCount || 0,
            sentCount: pushResult.sentCount || 0,
            failureCount: pushResult.failureCount || 0,
            invalidTokenCount: (pushResult.invalidTokens || []).length,
            errorSummary: pushResult.errorSummary || {}
        }
    };
};

const validateImageDataUrl = (dataUrl) => {
    if (typeof dataUrl !== 'string') return { ok: false, reason: 'Invalid image payload.' };
    if (!/^data:image\/[a-z0-9.+-]+;base64,/i.test(dataUrl)) {
        return { ok: false, reason: 'Invalid image format.' };
    }

    const parts = dataUrl.split(',', 2);
    if (parts.length !== 2) return { ok: false, reason: 'Invalid image payload.' };

    const bytes = estimateBase64Bytes(parts[1]);
    if (bytes > MAX_IMAGE_BYTES) {
        return { ok: false, reason: 'Image exceeds 2MB limit.' };
    }

    return { ok: true };
};

const checkRateLimit = (clientId) => {
    const now = Date.now();
    let record = rateLimitMap.get(clientId);
    if (!record || now - record.lastReset > RATE_LIMIT_WINDOW) record = { count: 0, lastReset: now };
    record.count++;
    rateLimitMap.set(clientId, record);
    return record.count <= RATE_LIMIT_MAX;
};

function heartbeat() { this.isAlive = true; }

const broadcastOnlineCount = () => {
    const count = wss.clients.size;
    const msg = JSON.stringify({ type: 'onlineCount', count });
    wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
};

const cleanupEphemeralMedia = async () => {
    try {
        await pool.query(
            `DELETE FROM ephemeral_media WHERE created_at < NOW() - INTERVAL '${EPHEMERAL_MEDIA_TTL_DAYS} days'`
        );
    } catch (e) {
        // Non-fatal. Table may not be ready on cold start.
        console.warn('ephemeral_media cleanup failed:', e.message);
    }
};

cleanupEphemeralMedia();
setInterval(cleanupEphemeralMedia, 6 * 60 * 60 * 1000); // every 6 hours

// --- DB Logic Helpers ---

async function getOrCreateUser(deviceId, ip) {
    try {
        let res = await pool.query('SELECT * FROM users_anon WHERE device_id = $1', [deviceId]);
        if (res.rows.length > 0) {
            // Update last seen
            await pool.query('UPDATE users_anon SET last_seen_at = NOW(), last_ip = $2 WHERE id = $1', [res.rows[0].id, ip]);
            return res.rows[0];
        } else {
            // Create
            res = await pool.query('INSERT INTO users_anon (device_id, last_ip) VALUES ($1, $2) RETURNING *', [deviceId, ip]);
            return res.rows[0];
        }
    } catch (e) {
        console.error('DB Error getOrCreateUser:', e);
        return null; // Fail safe
    }
}

async function setDbNickname(userId, nickname) {
    try {
        await pool.query('UPDATE users_anon SET nickname = $1, nickname_set_at = NOW() WHERE id = $2', [nickname, userId]);
        return true;
    } catch (e) { console.error(e); return false; }
}

async function checkBan(userId) {
    try {
        const res = await pool.query(`
            SELECT * FROM bans 
            WHERE user_id = $1 
            AND (ban_type = 'perm' OR ban_type = 'shadow' OR ban_until > NOW())
        `, [userId]);
        return res.rows[0];
    } catch (e) {
        console.error('DB Error checkBan:', e);
        return null;
    }
}

async function checkBlock(userAId, userBId) {
    try {
        const res = await pool.query(`
            SELECT 1 FROM blocks 
            WHERE (blocker_id = $1 AND blocked_id = $2) 
               OR (blocker_id = $2 AND blocked_id = $1)
        `, [userAId, userBId]);
        return res.rows.length > 0;
    } catch (e) {
        return false;
    }
}

const makePairKey = (userAId, userBId) => {
    const a = String(userAId || '').trim();
    const b = String(userBId || '').trim();
    if (!a || !b) return null;
    return a < b ? `${a}:${b}` : `${b}:${a}`;
};

const setPairRematchCooldown = (userAId, userBId, durationMs = MATCH_REMATCH_COOLDOWN_MS) => {
    const key = makePairKey(userAId, userBId);
    if (!key) return;
    pairRematchCooldowns.set(key, Date.now() + durationMs);
};

const isPairOnRematchCooldown = (userAId, userBId) => {
    const key = makePairKey(userAId, userBId);
    if (!key) return false;
    const expiresAt = Number(pairRematchCooldowns.get(key) || 0);
    if (!expiresAt) return false;
    if (expiresAt <= Date.now()) {
        pairRematchCooldowns.delete(key);
        return false;
    }
    return true;
};

async function blockUser(blockerId, blockedId) {
    if (blockerId === blockedId) return;
    try {
        await pool.query(
            'INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [blockerId, blockedId]
        );
    } catch (e) { console.error(e); }
}

async function createConversation(userAId, userBId) {
    try {
        const newId = uuidv4();
        const res = await pool.query(
            'INSERT INTO conversations (id, user_a_id, user_b_id) VALUES ($1, $2, $3) RETURNING id',
            [newId, userAId, userBId]
        );
        return res.rows[0].id;
    } catch (e) {
        console.error('DB Error createConversation:', e);
        throw e; // Propagate error to caller
    }
}

async function findOrCreatePersistentConversation(userAId, userBId) {
    try {
        // Find ANY existing conversation between these two (History is continuous)
        const res = await pool.query(`
            SELECT id FROM conversations 
            WHERE ((user_a_id = $1 AND user_b_id = $2) OR (user_a_id = $2 AND user_b_id = $1))
            ORDER BY started_at DESC LIMIT 1
        `, [userAId, userBId]);

        if (res.rows.length > 0) {
            console.log(`[DB] Found existing conversation ${res.rows[0].id} for ${userAId}<->${userBId}`);
            return res.rows[0].id;
        }

        // Create new one if none exists
        console.log(`[DB] Creating NEW conversation for ${userAId}<->${userBId}`);
        return await createConversation(userAId, userBId);
    } catch (e) {
        console.error('findOrCreatePersistentConversation error:', e);
        // Retry creation if query failed (e.g. connection glitch), but if createConversation throws, it propagates
        try {
            return await createConversation(userAId, userBId);
        } catch (creationError) {
            throw creationError;
        }
    }
}

async function endConversation(conversationId, reason) {
    if (!conversationId) return;
    try {
        await pool.query(
            'UPDATE conversations SET ended_at = NOW(), ended_reason = $1 WHERE id = $2',
            [reason, conversationId]
        );
    } catch (e) { console.error('DB Error endConversation:', e); }
}

async function logReport(reporterId, reportedId, conversationId, reason) {
    const cleanReason = String(reason || '').trim().slice(0, 800);
    const cleanConversationId = conversationId || null;
    if (!reporterId || !reportedId || !cleanReason) {
        return { error: 'invalid_input' };
    }
    if (reporterId === reportedId) {
        return { error: 'self_report_not_allowed' };
    }
    try {
        // Prevent duplicate report
        const check = cleanConversationId
            ? await pool.query(
                'SELECT id FROM reports WHERE reporter_user_id=$1 AND conversation_id=$2',
                [reporterId, cleanConversationId]
            )
            : await pool.query(
                `SELECT id
                 FROM reports
                 WHERE reporter_user_id=$1
                   AND reported_user_id=$2
                   AND created_at > NOW() - INTERVAL '24 hours'`,
                [reporterId, reportedId]
            );
        if (check.rows.length > 0) return { duplicate: true };

        await pool.query(
            'INSERT INTO reports (reporter_user_id, reported_user_id, conversation_id, reason) VALUES ($1, $2, $3, $4)',
            [reporterId, reportedId, cleanConversationId, cleanReason]
        );

        // Auto Ban Logic
        const reports24h = await pool.query(`
            SELECT COUNT(DISTINCT reporter_user_id) as cnt 
            FROM reports 
            WHERE reported_user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
        `, [reportedId]);

        if (parseInt(reports24h.rows[0].cnt) >= 3) {
            await pool.query(
                'INSERT INTO bans (user_id, ban_type, ban_until, reason, created_by) VALUES ($1, $2, NOW() + INTERVAL \'24 hours\', $3, $4)',
                [reportedId, 'temp', 'Auto-Ban: Too many reports (3 unique in 24h)', 'system']
            );
            return { banned: true };
        }

        return { banned: false };

    } catch (e) {
        console.error('DB Error logReport:', e);
        return { error: e?.message || 'db_error' };
    }
}


// --- Main Logic ---

const removeFromQueue = (clientId) => {
    waitingQueue = waitingQueue.filter(item => item.clientId !== clientId);
};

const createRoom = (roomId, conversationId, userA, userB) => {
    rooms.set(roomId, {
        users: [
            { clientId: userA.clientId, nickname: userA.nickname, username: userA.username, dbUserId: userA.dbUserId },
            { clientId: userB.clientId, nickname: userB.nickname, username: userB.username, dbUserId: userB.dbUserId }
        ],
        sockets: {
            [userA.clientId]: userA.ws,
            [userB.clientId]: userB.ws
        },
        conversationId: conversationId
    });

    userRoomMap.set(userA.clientId, roomId);
    userRoomMap.set(userB.clientId, roomId);

    sendJson(userA.ws, { type: 'matched', roomId, peerNickname: userB.nickname, peerUsername: userB.username, peerId: userB.dbUserId }); // V13: add peerId
    sendJson(userB.ws, { type: 'matched', roomId, peerNickname: userA.nickname, peerUsername: userA.username, peerId: userA.dbUserId });
};

const getPendingMatchForClient = (clientId) => {
    const matchId = userPendingMatchMap.get(clientId);
    if (!matchId) return null;
    const pending = pendingMatches.get(matchId);
    if (!pending) {
        userPendingMatchMap.delete(clientId);
        return null;
    }
    const participantIndex = pending.users.findIndex((u) => u.clientId === clientId);
    if (participantIndex === -1) {
        userPendingMatchMap.delete(clientId);
        return null;
    }
    return { matchId, pending, participantIndex };
};

const clearPendingMatchById = (matchId) => {
    const pending = pendingMatches.get(matchId);
    if (!pending) return null;
    if (pending.timer) clearTimeout(pending.timer);
    pendingMatches.delete(matchId);
    pending.users.forEach((u) => userPendingMatchMap.delete(u.clientId));
    return pending;
};

const queueClientForRematch = (clientId) => {
    setTimeout(() => {
        const clientData = activeClients.get(clientId);
        if (!clientData?.ws || clientData.ws.readyState !== WebSocket.OPEN) return;
        joinQueue(clientData.ws).catch((e) => {
            console.error('queueClientForRematch error:', e?.message || e);
        });
    }, 0);
};

const cancelPendingMatchById = (
    matchId,
    {
        actorClientId = null,
        actorReason = null,
        peerReason = null,
        requeueActor = false,
        requeuePeers = true
    } = {}
) => {
    const pending = clearPendingMatchById(matchId);
    if (!pending) return false;

    pending.users.forEach((participant) => {
        const ws = activeClients.get(participant.clientId)?.ws || participant.ws;
        if (!ws || ws.readyState !== WebSocket.OPEN) return;

        const isActor = actorClientId && participant.clientId === actorClientId;
        const reason = isActor ? actorReason : peerReason;
        if (!reason) return;

        sendJson(ws, { type: 'match_offer_closed', reason });
    });

    pending.users.forEach((participant) => {
        const isActor = actorClientId && participant.clientId === actorClientId;
        const shouldRequeue = isActor ? requeueActor : requeuePeers;
        if (shouldRequeue) queueClientForRematch(participant.clientId);
    });

    return true;
};

const cancelPendingMatchForClient = (clientId, options = {}) => {
    const context = getPendingMatchForClient(clientId);
    if (!context) return false;
    return cancelPendingMatchById(context.matchId, { actorClientId: clientId, ...options });
};

const finalizePendingMatchIfReady = async (matchId) => {
    const pending = pendingMatches.get(matchId);
    if (!pending || pending.finalized) return false;
    if (!pending.users.every((u) => u.decision === 'accepted')) return false;

    pending.finalized = true;
    const participants = pending.users.map((participant) => {
        const live = activeClients.get(participant.clientId);
        if (!live?.ws || live.ws.readyState !== WebSocket.OPEN) return null;
        return {
            clientId: participant.clientId,
            ws: live.ws,
            nickname: live.nickname || participant.nickname,
            username: live.username || participant.username,
            dbUserId: live.dbUserId || participant.dbUserId
        };
    }).filter(Boolean);

    clearPendingMatchById(matchId);

    if (participants.length !== 2) {
        participants.forEach((participant) => queueClientForRematch(participant.clientId));
        return false;
    }

    let conversationId = null;
    try {
        conversationId = await createConversation(participants[0].dbUserId, participants[1].dbUserId);
    } catch (e) {
        participants.forEach((participant) => {
            sendError(participant.ws, 'DB_ERROR');
            queueClientForRematch(participant.clientId);
        });
        return false;
    }

    const roomId = uuidv4();
    createRoom(roomId, conversationId, participants[0], participants[1]);
    return true;
};

const createPendingMatch = (userA, userB) => {
    const matchId = uuidv4();
    const autoAcceptAt = Date.now() + MATCH_CONFIRM_TIMEOUT_MS;
    const pending = {
        id: matchId,
        users: [
            {
                clientId: userA.clientId,
                ws: userA.ws,
                nickname: userA.nickname,
                username: userA.username,
                dbUserId: userA.dbUserId,
                decision: 'pending'
            },
            {
                clientId: userB.clientId,
                ws: userB.ws,
                nickname: userB.nickname,
                username: userB.username,
                dbUserId: userB.dbUserId,
                decision: 'pending'
            }
        ],
        autoAcceptAt,
        timeoutMs: MATCH_CONFIRM_TIMEOUT_MS,
        timer: null,
        finalized: false
    };

    pendingMatches.set(matchId, pending);
    pending.users.forEach((participant) => userPendingMatchMap.set(participant.clientId, matchId));

    pending.users.forEach((participant) => {
        const peer = pending.users.find((u) => u.clientId !== participant.clientId);
        if (!peer || participant.ws.readyState !== WebSocket.OPEN) return;
        sendJson(participant.ws, {
            type: 'match_offer',
            matchId,
            peerNickname: peer.nickname,
            peerUsername: peer.username,
            peerId: peer.dbUserId,
            autoAcceptAt,
            timeoutMs: MATCH_CONFIRM_TIMEOUT_MS
        });
    });

    pending.timer = setTimeout(() => {
        const current = pendingMatches.get(matchId);
        if (!current) return;
        current.users.forEach((participant) => {
            if (participant.decision === 'pending') participant.decision = 'accepted';
        });
        finalizePendingMatchIfReady(matchId).catch((e) => {
            console.error('pending match auto-accept finalize error:', e?.message || e);
            cancelPendingMatchById(matchId, {
                actorReason: 'server_error',
                peerReason: 'server_error',
                requeueActor: true,
                requeuePeers: true
            });
        });
    }, MATCH_CONFIRM_TIMEOUT_MS + 25);
};

const applyMatchDecision = async (ws, providedMatchId, decision) => {
    const context = getPendingMatchForClient(ws.clientId);
    if (!context) return;

    const { matchId, pending, participantIndex } = context;
    if (providedMatchId && providedMatchId !== matchId) return;

    const participant = pending.users[participantIndex];
    if (!participant) return;

    if (decision === 'accept') {
        participant.decision = 'accepted';
        sendJson(ws, { type: 'match_offer_waiting' });
        await finalizePendingMatchIfReady(matchId);
        return;
    }

    participant.decision = 'rejected';
    const first = pending.users[0] || null;
    const second = pending.users[1] || null;
    if (first?.dbUserId && second?.dbUserId) {
        setPairRematchCooldown(first.dbUserId, second.dbUserId);
    }
    cancelPendingMatchById(matchId, {
        actorClientId: ws.clientId,
        actorReason: null,
        peerReason: 'peer_rejected',
        requeueActor: true,
        requeuePeers: true
    });
};

const joinQueue = async (ws) => {
    const clientData = activeClients.get(ws.clientId);
    if (!clientData || !clientData.dbUserId) return sendError(ws, 'AUTH_ERROR');

    // Require nickname (V6)
    if (!clientData.nickname) {
        return sendError(ws, 'NO_NICKNAME');
    }

    // Ban Check
    const ban = await checkBan(clientData.dbUserId);
    if (ban) {
        if (ban.ban_type === 'shadow') {
            sendJson(ws, { type: 'queued' });
            return;
        }
        const lang = resolveWsLang(ws);
        return sendError(
            ws,
            'BANNED',
            t(lang, 'ws.BANNED_REASON', { reason: ban.reason || '-' }, t(lang, 'ws.BANNED', {}, 'Account is suspended.'))
        );
    }

    cancelPendingMatchForClient(ws.clientId, {
        actorReason: null,
        peerReason: 'peer_cancelled',
        requeueActor: false,
        requeuePeers: true
    });
    leaveRoom(ws.clientId);
    removeFromQueue(ws.clientId);

    waitingQueue = waitingQueue.filter((item) => (
        item
        && item.clientId
        && item.ws
        && item.ws.readyState === WebSocket.OPEN
        && activeClients.has(item.clientId)
    ));

    const me = {
        clientId: ws.clientId,
        ws,
        nickname: clientData.nickname,
        username: clientData.username, // V13: Pass username
        dbUserId: clientData.dbUserId
    };

    if (waitingQueue.length > 0) {
        let peerIndex = -1;
        let peer = null;

        for (let i = 0; i < waitingQueue.length; i++) {
            const p = waitingQueue[i];
            if (!p || p.clientId === me.clientId) continue;

            const blocked = await checkBlock(me.dbUserId, p.dbUserId);
            if (!blocked && !isPairOnRematchCooldown(me.dbUserId, p.dbUserId)) {
                peerIndex = i;
                peer = p;
                break;
            }
        }

        if (peer && peerIndex !== -1) {
            waitingQueue.splice(peerIndex, 1);
            createPendingMatch(me, peer);
        } else {
            waitingQueue.push(me);
            sendJson(ws, { type: 'queued' });
        }
    } else {
        waitingQueue.push(me);
        sendJson(ws, { type: 'queued' });
    }
};

const leaveRoom = (clientId, reason = 'leave') => {
    const roomId = userRoomMap.get(clientId);
    if (!roomId) return;

    const room = rooms.get(roomId);
    if (room) {
        if (Array.isArray(room.users) && room.users.length === 2) {
            const userA = room.users[0];
            const userB = room.users[1];
            if (userA?.dbUserId && userB?.dbUserId) {
                setPairRematchCooldown(userA.dbUserId, userB.dbUserId);
            }
        }
        endConversation(room.conversationId, reason);

        recentRooms.set(roomId, {
            users: [...room.users],
            timestamp: Date.now(),
            conversationId: room.conversationId
        });

        room.users.forEach(u => {
            const id = u.clientId;
            const ws = room.sockets[id];
            if (ws) sendJson(ws, { type: 'ended', roomId, reason: id === clientId ? reason : 'peer_left' });
            userRoomMap.delete(id);
        });
        rooms.delete(roomId);
    } else {
        userRoomMap.delete(clientId);
    }
};


wss.on('connection', (ws, req) => {
    ws.clientId = uuidv4();
    ws.isAlive = true;
    ws.limiter = { count: 0, lastReset: Date.now() }; // Security: Rate Limiter Init
    ws.prefLang = resolveLangFromHeaders(req.headers || {});
    ws.on('pong', heartbeat);

    broadcastOnlineCount();
    sendJson(ws, { type: 'hello', clientId: ws.clientId });

    ws.on('message', async (raw) => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        // Security: WebSocket Rate Limiting
        const now = Date.now();
        if (now - ws.limiter.lastReset > 1000) {
            ws.limiter.count = 0;
            ws.limiter.lastReset = now;
        }
        ws.limiter.count++;

        if (ws.limiter.count > 5) {
            if (ws.limiter.count > 10) return ws.close(); // Hard Limit
            sendError(ws, 'RATE_LIMIT');
            return;
        }

        if (data.type === 'hello_ack') {
            const deviceId = data.deviceId;
            const requestedLang = normalizeLang(data.lang || ws.prefLang, 'en');
            let dbUser = null;
            let isAnon = false;

            if (data.token) {
                // Token Auth
                const { hashToken } = require('./utils/security');
                const tokenHash = hashToken(data.token);
                try {
                    const sessionRes = await pool.query(`
                        SELECT s.*, u.id as user_id, u.username, u.status, p.display_name
                        FROM sessions s
                        JOIN users u ON s.user_id = u.id
                        LEFT JOIN profiles p ON u.id = p.user_id
                        WHERE s.token_hash = $1 AND s.expires_at > NOW()
                     `, [tokenHash]);

                    if (sessionRes.rows.length > 0) {
                        const session = sessionRes.rows[0];
                        dbUser = {
                            id: session.user_id,
                            username: session.username,
                            nickname: session.display_name || session.username, // Use Display Name as nickname in chat
                            status: session.status
                        };
                    }
                } catch (e) { console.error('Token Auth Error', e); }
            }

            // Fallback to Anon (Legacy / Guest) if no token or token invalid
            if (!dbUser) {
                // For now, allow anon fallback if we supported it. 
                // But since UI enforces login, this might mean "Session Expired"
                // Let's send AUTH_ERROR if token was provided but failed.
                if (data.token) {
                    return sendError(ws, 'AUTH_ERROR');
                }
                // If no token was provided at all (legacy client?), use getOrCreateUser
                dbUser = await getOrCreateUser(deviceId, req.socket.remoteAddress);
                isAnon = true;
            }

            if (!dbUser) return sendError(ws, 'DB_ERROR');

            // Check Status
            if (dbUser.status && dbUser.status !== 'active') {
                return sendError(ws, 'BANNED');
            }

            // Check Bans
            const ban = await checkBan(dbUser.id);
            if (ban && ban.ban_type !== 'shadow') {
                const lang = requestedLang || resolveWsLang(ws);
                const untilText = ban.ban_until
                    ? new Date(ban.ban_until).toLocaleString()
                    : t(lang, 'ws.BANNED_INDEFINITE', {}, 'Indefinite');
                sendError(
                    ws,
                    'BANNED',
                    t(lang, 'ws.BANNED_UNTIL_REASON', { until: untilText, reason: ban.reason || '-' }, t(lang, 'ws.BANNED', {}, 'Account is suspended.'))
                );
                ws.close();
                return;
            }

            const isShadow = ban && ban.ban_type === 'shadow';
            activeClients.set(ws.clientId, {
                ws,
                dbUserId: dbUser.id,
                deviceId: deviceId || 'unknown',
                isShadowBanned: isShadow,
                nickname: dbUser.nickname, // Display Name
                username: dbUser.username,  // V13: Store unique username
                platform: data.platform === 'android' ? 'android' : 'web',
                lang: requestedLang
            });

            sendJson(ws, { type: 'welcome', nickname: dbUser.nickname, lang: requestedLang });
            return;
        }

        const clientData = activeClients.get(ws.clientId);
        if (!clientData && data.type !== 'hello_ack') return;

        switch (data.type) {
            case 'setNickname':
                // V6: Persistent Nickname Registration
                let uname = (data.nickname || "").trim();
                const check = validateUsername(uname);
                if (!check.valid) {
                    return sendError(ws, 'INVALID_NICKNAME', check.reason);
                }

                await setDbNickname(clientData.dbUserId, uname);
                clientData.nickname = uname; // Update memory
                sendJson(ws, { type: 'welcome', nickname: uname });
                break;

            case 'joinQueue':
                await joinQueue(ws);
                break;

            case 'matchDecision':
                {
                    const decision = toText(data.decision, '').trim().toLowerCase();
                    const matchId = toText(data.matchId, '').trim();
                    if (decision !== 'accept' && decision !== 'reject') {
                        const lang = resolveWsLang(ws);
                        sendError(ws, 'INVALID_INPUT', t(lang, 'errors.INVALID_INPUT', {}, 'Invalid request.'));
                        break;
                    }
                    await applyMatchDecision(ws, matchId, decision);
                }
                break;

            case 'message':
                const roomId = userRoomMap.get(ws.clientId);
                if (roomId && roomId === data.roomId) {
                    const room = rooms.get(roomId);
                    if (room) {
                        const peerObj = room.users.find(u => u.clientId !== ws.clientId);
                        if (peerObj && room.sockets[peerObj.clientId]) {
                            // Admin Log
                            if (adminRoutes.logToAdmin) {
                                adminRoutes.logToAdmin({
                                    type: 'msg',
                                    from: clientData.nickname || 'User',
                                    to: peerObj.nickname || 'Peer',
                                    content: data.text
                                });
                            }

                            sendJson(room.sockets[peerObj.clientId], {
                                type: 'message',
                                roomId,
                                from: 'peer',
                                text: data.text
                            });

                            // Anonymous room messages are intentionally ephemeral.
                            // Persistence is only supported in friend/direct conversations.
                        }
                    }
                }
                break;

            case 'direct_message':
                {
                    const dmTargetUserId = data.targetUserId;
                    const dmText = toText(data.text, '').trim();
                    const clientMsgId = toClientMsgId(data.clientMsgId);
                    const dmSenderId = clientData.dbUserId;

                    if (!dmTargetUserId || !dmText) {
                        sendError(ws, 'INVALID_MESSAGE_REQUEST', null, { clientMsgId: clientMsgId || undefined });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId: clientMsgId || null, status: 'failed' });
                        break;
                    }

                    if (!clientMsgId) {
                        sendError(ws, 'INVALID_MESSAGE_ID');
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId: null, status: 'failed' });
                        break;
                    }

                    try {
                        const fCheck = await pool.query(
                            'SELECT 1 FROM friendships WHERE ((user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)) AND status=\'accepted\'',
                            [dmSenderId, dmTargetUserId]
                        );
                        if (fCheck.rows.length === 0) {
                            sendError(ws, 'NOT_FRIEND', null, { clientMsgId });
                            sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                            break;
                        }
                    } catch (e) {
                        console.error('direct_message friendship check error:', e.message);
                        sendError(ws, 'FRIENDSHIP_CHECK_FAILED', null, { clientMsgId });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                        break;
                    }

                    let convId = null;
                    try {
                        convId = await findOrCreatePersistentConversation(dmSenderId, dmTargetUserId);
                    } catch (e) {
                        console.error('direct_message conversation error:', e.message);
                        sendError(ws, 'CONVERSATION_CREATE_FAILED', null, { clientMsgId });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                        break;
                    }

                    if (!convId) {
                        sendError(ws, 'CONVERSATION_CREATE_FAILED', null, { clientMsgId });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                        break;
                    }

                    let persistedMessageId = null;
                    let isDuplicate = false;
                    try {
                        const existing = await pool.query(
                            'SELECT id, conversation_id FROM messages WHERE sender_id = $1 AND client_msg_id = $2 LIMIT 1',
                            [dmSenderId, clientMsgId]
                        );
                        if (existing.rows.length > 0) {
                            isDuplicate = true;
                            persistedMessageId = existing.rows[0].id;
                            convId = existing.rows[0].conversation_id || convId;
                        } else {
                            const ins = await pool.query(
                                'INSERT INTO messages (conversation_id, sender_id, client_msg_id, text, msg_type) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                                [convId, dmSenderId, clientMsgId, dmText, 'direct']
                            );
                            persistedMessageId = ins.rows[0].id;
                        }
                    } catch (e) {
                        console.error('direct_message persist error:', e.message);
                        sendError(ws, 'MESSAGE_PERSIST_FAILED', null, { clientMsgId });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                        break;
                    }

                    if (isDuplicate) {
                        sendJson(ws, {
                            type: 'direct_message_ack',
                            clientMsgId,
                            status: 'duplicate',
                            serverMessageId: persistedMessageId,
                            conversationId: convId
                        });
                        break;
                    }

                    const dmDeliveryId = uuidv4();

                    let dmTargetClient = null;
                    for (const [, cData] of activeClients) {
                        if (cData.dbUserId === dmTargetUserId) {
                            dmTargetClient = cData;
                            break;
                        }
                    }

                    if (dmTargetClient) {
                        sendJson(dmTargetClient.ws, {
                            type: 'direct_message',
                            fromUsername: clientData.username,
                            fromNickname: clientData.nickname,
                            fromUserId: dmSenderId,
                            msgType: 'direct',
                            text: dmText,
                            conversationId: convId || null,
                            deliveryId: dmDeliveryId,
                            clientMsgId
                        });
                    }

                    const dmPushDebounce = shouldDebouncePush({
                        targetUserId: dmTargetUserId,
                        conversationId: convId || 'no-conversation',
                        eventType: 'direct_message'
                    });

                    if (dmPushDebounce.debounced) {
                        logDebouncedPush({
                            deliveryId: dmDeliveryId,
                            eventType: 'direct_message_debounced',
                            targetUserId: dmTargetUserId,
                            conversationId: convId || null,
                            channelId: PUSH_CHANNEL_IDS.messages,
                            debounce: dmPushDebounce
                        });
                    } else {
                        const dmTargetLang = await resolveUserLang(dmTargetUserId, normalizeLang(dmTargetClient?.lang, 'en'));
                        sendPushToUser(dmTargetUserId, {
                            title: clientData.nickname || clientData.username || t(dmTargetLang, 'ws.NEW_MESSAGE', {}, 'New message'),
                            body: dmText.slice(0, 140),
                            ttlSeconds: 3600,
                            collapseKey: `direct_${String(convId || dmTargetUserId).slice(0, 64)}`,
                            channelId: PUSH_CHANNEL_IDS.messages,
                            data: {
                                type: 'direct_message',
                                fromUserId: dmSenderId,
                                fromUsername: clientData.username || '',
                                fromNickname: clientData.nickname || '',
                                msgType: 'direct',
                                text: dmText.slice(0, 140),
                                conversationId: convId || '',
                                deliveryId: dmDeliveryId,
                                clientMsgId,
                                channelId: PUSH_CHANNEL_IDS.messages
                            }
                        }, {
                            eventType: 'direct_message',
                            deliveryId: dmDeliveryId
                        }).catch((e) => console.error('direct_message push error:', e.message));
                    }

                    sendJson(ws, {
                        type: 'direct_message_ack',
                        clientMsgId,
                        status: 'sent',
                        serverMessageId: persistedMessageId,
                        conversationId: convId
                    });
                }
                break;

            case 'typing':
            case 'stop_typing':
                if (data.targetUserId) {
                    // Friend Typing
                    let tClient = null;
                    for (const [cid, cData] of activeClients) {
                        if (cData.dbUserId === data.targetUserId) {
                            tClient = cData;
                            break;
                        }
                    }
                    if (tClient) {
                        console.log(`[DEBUG] Relay typing event '${data.type}' from ${clientData.nickname} to ${tClient.nickname}`);
                        sendJson(tClient.ws, {
                            type: data.type,
                            fromUserId: clientData.dbUserId
                        });
                    } else {
                        console.log(`[DEBUG] Typing target ${data.targetUserId} not found/online.`);
                    }
                } else {
                    // Anon Typing
                    const tRoomId = userRoomMap.get(ws.clientId);
                    if (tRoomId) {
                        const room = rooms.get(tRoomId);
                        if (room) {
                            const peerObj = room.users.find(u => u.clientId !== ws.clientId);
                            if (peerObj && room.sockets[peerObj.clientId]) {
                                sendJson(room.sockets[peerObj.clientId], {
                                    type: data.type
                                });
                            }
                        }
                    }
                }
                break;

            case 'leaveQueue': // Handle cancel waiting/match offer
                removeFromQueue(ws.clientId);
                cancelPendingMatchForClient(ws.clientId, {
                    actorReason: null,
                    peerReason: 'peer_cancelled',
                    requeueActor: false,
                    requeuePeers: true
                });
                break;

            case 'next':
                cancelPendingMatchForClient(ws.clientId, {
                    actorReason: null,
                    peerReason: 'peer_rejected',
                    requeueActor: false,
                    requeuePeers: true
                });
                leaveRoom(ws.clientId, 'next');
                await joinQueue(ws); // Join with existing nickname
                break;

            case 'leave':
                removeFromQueue(ws.clientId);
                cancelPendingMatchForClient(ws.clientId, {
                    actorReason: null,
                    peerReason: 'peer_cancelled',
                    requeueActor: false,
                    requeuePeers: true
                });
                leaveRoom(ws.clientId, 'leave');
                break;

            case 'image_send':
                if (!data.roomId || !data.imageData) return;
                {
                    const v = validateImageDataUrl(data.imageData);
                    if (!v.ok) return sendError(ws, 'INVALID_IMAGE');
                }
                const iRoomId = userRoomMap.get(ws.clientId);
                if (iRoomId !== data.roomId) return;
                const iRoom = rooms.get(iRoomId);
                if (!iRoom) return;

                const iSender = iRoom.users.find(u => u.clientId === ws.clientId);
                const iReceiver = iRoom.users.find(u => u.clientId !== ws.clientId);

                if (!iSender || !iReceiver) return;

                // Check Friendship
                let isFriend = false;
                try {
                    const fRes = await pool.query(
                        'SELECT 1 FROM friendships WHERE ((user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)) AND status=\'accepted\'',
                        [iSender.dbUserId, iReceiver.dbUserId]
                    );
                    isFriend = fRes.rows.length > 0;
                } catch (e) { }

                if (!isFriend) return sendError(ws, 'NOT_FRIEND');

                // Store
                try {
                    const insertRes = await pool.query(
                        'INSERT INTO ephemeral_media (sender_id, receiver_id, media_data) VALUES ($1, $2, $3) RETURNING id',
                        [iSender.dbUserId, iReceiver.dbUserId, data.imageData]
                    );
                    const mediaId = insertRes.rows[0].id;

                    // Notify Receiver
                    if (iRoom.sockets[iReceiver.clientId]) {
                        sendJson(iRoom.sockets[iReceiver.clientId], {
                            type: 'message',
                            roomId: iRoomId,
                            senderNickname: iSender.nickname, // Standardize with normal message
                            from: 'peer',
                            msgType: 'image',
                            mediaId: mediaId,
                            text: t(resolveWsLang(iRoom.sockets[iReceiver.clientId]), 'ws.PHOTO_SENT', {}, 'Photo sent')
                        });
                        // Admin Log
                        if (adminRoutes.logToAdmin) {
                            adminRoutes.logToAdmin({
                                type: 'msg',
                                from: iSender.nickname || 'User',
                                to: iReceiver.nickname || 'Peer',
                                content: '[PHOTO SENT]'
                            });
                        }
                    }
                    // Notify Sender (Echo)
                    sendJson(ws, {
                        type: 'message', // Echo as message to show in own chat? 
                        // Actually App.jsx handles generic message send confirmation differently
                        // But for image we need to show bubble too.
                        // Let's send a custom ack or handle locally?
                        // Handle locally in frontend (optimistic) or wait for confirmation.
                        // Let's send 'image_sent'
                        type: 'image_sent',
                        mediaId
                    });
                } catch (e) { console.error(e); }
                break;

            case 'fetch_image':
                if (!data.mediaId) return;
                if (!isUuid(data.mediaId)) {
                    return sendJson(ws, {
                        type: 'image_error',
                        code: 'INVALID_MEDIA_ID',
                        mediaId: data.mediaId,
                        message: t(resolveWsLang(ws), 'ws.INVALID_MEDIA_ID', {}, 'Invalid media id.')
                    });
                }
                const clientDataFetch = activeClients.get(ws.clientId);
                if (!clientDataFetch || !clientDataFetch.dbUserId) return;

                try {
                    const res = await pool.query(
                        'SELECT * FROM ephemeral_media WHERE id = $1 AND receiver_id = $2',
                        [data.mediaId, clientDataFetch.dbUserId]
                    );

                    if (res.rows.length === 0) {
                        return sendJson(ws, {
                            type: 'image_error',
                            code: 'MEDIA_EXPIRED',
                            mediaId: data.mediaId,
                            message: t(resolveWsLang(ws), 'ws.MEDIA_EXPIRED', {}, 'Photo expired.')
                        });
                    }

                    const item = res.rows[0];
                    sendJson(ws, { type: 'image_data', mediaId: data.mediaId, imageData: item.media_data });

                    // DELETE immediately
                    await pool.query('DELETE FROM ephemeral_media WHERE id = $1', [data.mediaId]);
                } catch (e) { console.error(e); }
                break;

            case 'direct_image_send':
                {
                    const distTargetUserId = data.targetUserId;
                    const distSenderId = clientData.dbUserId;
                    const clientMsgId = toClientMsgId(data.clientMsgId);

                    if (!distTargetUserId || !data.imageData) {
                        sendError(ws, 'INVALID_PHOTO_REQUEST', null, { clientMsgId: clientMsgId || undefined });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId: clientMsgId || null, status: 'failed' });
                        break;
                    }

                    if (!clientMsgId) {
                        sendError(ws, 'INVALID_MESSAGE_ID');
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId: null, status: 'failed' });
                        break;
                    }

                    const v = validateImageDataUrl(data.imageData);
                    if (!v.ok) {
                        sendError(ws, 'INVALID_IMAGE', null, { clientMsgId });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                        break;
                    }

                    try {
                        const fRes = await pool.query(
                            'SELECT 1 FROM friendships WHERE ((user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)) AND status=\'accepted\'',
                            [distSenderId, distTargetUserId]
                        );
                        if (fRes.rows.length === 0) {
                            sendError(ws, 'NOT_FRIEND', null, { clientMsgId });
                            sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                            break;
                        }

                        const existing = await pool.query(
                            'SELECT id, conversation_id, media_id FROM messages WHERE sender_id = $1 AND client_msg_id = $2 LIMIT 1',
                            [distSenderId, clientMsgId]
                        );
                        if (existing.rows.length > 0) {
                            const row = existing.rows[0];
                            sendJson(ws, {
                                type: 'direct_message_ack',
                                clientMsgId,
                                status: 'duplicate',
                                serverMessageId: row.id,
                                conversationId: row.conversation_id,
                                mediaId: row.media_id
                            });
                            break;
                        }

                        const dConvId = await findOrCreatePersistentConversation(distSenderId, distTargetUserId);
                        if (!dConvId) {
                            sendError(ws, 'CONVERSATION_CREATE_FAILED', null, { clientMsgId });
                            sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                            break;
                        }

                        const dInsertRes = await pool.query(
                            'INSERT INTO ephemeral_media (sender_id, receiver_id, media_data) VALUES ($1, $2, $3) RETURNING id',
                            [distSenderId, distTargetUserId, data.imageData]
                        );
                        const dMediaId = dInsertRes.rows[0].id;

                        const messageInsert = await pool.query(
                            'INSERT INTO messages (conversation_id, sender_id, client_msg_id, text, msg_type, media_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                            [dConvId, distSenderId, clientMsgId, 'Photo sent', 'image', dMediaId]
                        );
                        const serverMessageId = messageInsert.rows[0].id;

                        let dTargetClient = null;
                        for (const [, cData] of activeClients) {
                            if (cData.dbUserId === distTargetUserId) {
                                dTargetClient = cData;
                                break;
                            }
                        }

                        const dTargetLang = await resolveUserLang(distTargetUserId, normalizeLang(dTargetClient?.lang, 'en'));
                        const localizedPhotoText = t(dTargetLang, 'ws.PHOTO_SENT', {}, 'Photo sent');
                        const imageDeliveryId = uuidv4();
                        if (dTargetClient) {
                            sendJson(dTargetClient.ws, {
                                type: 'direct_message',
                                fromUserId: distSenderId,
                                fromUsername: clientData.username,
                                fromNickname: clientData.nickname,
                                msgType: 'image',
                                mediaId: dMediaId,
                                text: localizedPhotoText,
                                conversationId: dConvId,
                                deliveryId: imageDeliveryId,
                                clientMsgId
                            });
                        }

                        const imagePushDebounce = shouldDebouncePush({
                            targetUserId: distTargetUserId,
                            conversationId: dConvId || 'no-conversation',
                            eventType: 'direct_image_send'
                        });

                        if (imagePushDebounce.debounced) {
                            logDebouncedPush({
                                deliveryId: imageDeliveryId,
                                eventType: 'direct_image_debounced',
                                targetUserId: distTargetUserId,
                                conversationId: dConvId || null,
                                channelId: PUSH_CHANNEL_IDS.messages,
                                debounce: imagePushDebounce
                            });
                        } else {
                            sendPushToUser(distTargetUserId, {
                                title: clientData.nickname || clientData.username || t(dTargetLang, 'ws.NEW_MESSAGE', {}, 'New message'),
                                body: localizedPhotoText,
                                ttlSeconds: 3600,
                                collapseKey: `direct_${String(dConvId || distTargetUserId).slice(0, 64)}`,
                                channelId: PUSH_CHANNEL_IDS.messages,
                                data: {
                                    type: 'direct_message',
                                    fromUserId: distSenderId,
                                    fromUsername: clientData.username || '',
                                    fromNickname: clientData.nickname || '',
                                    msgType: 'image',
                                    mediaId: dMediaId,
                                    text: localizedPhotoText,
                                    conversationId: dConvId || '',
                                    deliveryId: imageDeliveryId,
                                    clientMsgId,
                                    channelId: PUSH_CHANNEL_IDS.messages
                                }
                            }, {
                                eventType: 'direct_image_send',
                                deliveryId: imageDeliveryId
                            }).catch((e) => console.error('direct_image_send push error:', e.message));
                        }

                        sendJson(ws, {
                            type: 'image_sent',
                            mediaId: dMediaId,
                            targetUserId: distTargetUserId,
                            clientMsgId
                        });

                        sendJson(ws, {
                            type: 'direct_message_ack',
                            clientMsgId,
                            status: 'sent',
                            serverMessageId,
                            conversationId: dConvId,
                            mediaId: dMediaId
                        });
                    } catch (e) {
                        console.error('direct_image_send error', e);
                        sendError(ws, 'PHOTO_SEND_FAILED', null, { clientMsgId });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                    }
                }
                break;


            case 'report':
                {
                    const reason = String(data.reason || '').trim();
                    if (!reason) {
                        sendError(ws, 'INVALID_INPUT');
                        break;
                    }

                    const targetUserId = String(data.targetUserId || '').trim() || null;
                    const conversationIdHint = String(data.conversationId || '').trim() || null;
                    const reportResult = await handleReport({
                        reporterClientId: ws.clientId,
                        reporterDbUserId: clientData.dbUserId,
                        roomId: data.roomId || null,
                        targetUserId,
                        conversationIdHint,
                        reason
                    });

                    if (!reportResult?.ok) {
                        const lang = resolveWsLang(ws);
                        sendError(
                            ws,
                            'SERVER_ERROR',
                            reportResult?.message || t(lang, 'ws.REPORT_FAILED', {}, 'Report could not be recorded right now. Please try again.')
                        );
                        break;
                    }

                    sendJson(ws, {
                        type: 'success',
                        code: 'REPORT_OK',
                        duplicate: !!reportResult.duplicate,
                        message: t(resolveWsLang(ws), 'ws.REPORT_OK', {}, 'Your report has been sent.')
                    });
                }
                break;

            case 'joinDirect':
                if (data.targetUsername) {
                    const targetUname = data.targetUsername.toLowerCase().trim();
                    const meId = clientData.dbUserId;

                    // 1. Find Target User ID
                    let targetUser = null;
                    try {
                        const tRes = await pool.query('SELECT id FROM users WHERE username = $1', [targetUname]);
                        targetUser = tRes.rows[0];
                    } catch (e) { console.error(e); }

                    if (!targetUser) return sendError(ws, 'NOT_FOUND');

                    // 2. Check Friendship
                    let isFriend = false;
                    try {
                        const fRes = await pool.query(
                            'SELECT 1 FROM friendships WHERE ((user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)) AND status=\'accepted\'',
                            [meId, targetUser.id]
                        );
                        isFriend = fRes.rows.length > 0;
                    } catch (e) { console.error(e); }

                    if (!isFriend) return sendError(ws, 'NOT_FRIEND');

                    // 3. Check if Target is Online
                    let targetClient = null;
                    for (const [cid, cData] of activeClients) {
                        if (cData.dbUserId === targetUser.id) {
                            targetClient = cData;
                            break;
                        }
                    }

                    if (targetClient) {
                        // V13: Do NOT force leaveRoom anymore.
                        // Keep direct chat session persistent across reconnects.
                        const conversationId = await findOrCreatePersistentConversation(meId, targetUser.id);

                        sendJson(ws, {
                            type: 'direct_matched',
                            targetUsername: targetClient.nickname,
                            targetUserId: targetUser.id,
                            conversationId
                        });
                        return;
                    } else {
                        return sendError(ws, 'OFFLINE');
                    }
                }
                break;
        }
    });

    ws.on('close', () => {
        cancelPendingMatchForClient(ws.clientId, {
            actorReason: null,
            peerReason: 'peer_disconnected',
            requeueActor: false,
            requeuePeers: true
        });
        if (activeClients.has(ws.clientId)) activeClients.delete(ws.clientId);
        removeFromQueue(ws.clientId);
        leaveRoom(ws.clientId, 'disconnect');
        broadcastOnlineCount();
    });
});

const handleReport = async ({
    reporterClientId,
    reporterDbUserId,
    roomId,
    targetUserId,
    conversationIdHint,
    reason
}) => {
    const cleanReason = String(reason || '').trim().slice(0, 800);
    if (!cleanReason) {
        return { ok: false, message: 'Rapor nedeni gerekli.' };
    }

    let users = null;
    let conversationId = null;
    if (roomId) {
        const room = rooms.get(roomId);
        if (room) {
            users = room.users;
            conversationId = room.conversationId;
        } else {
            const recent = recentRooms.get(roomId);
            if (recent) {
                users = recent.users;
                conversationId = recent.conversationId;
            }
        }
    }

    let reporterId = reporterDbUserId || null;
    let reportedId = targetUserId || null;
    let reportedClientId = null;

    if (users && users.length) {
        const reporterObj = users.find((u) => u.clientId === reporterClientId);
        const reportedObj = users.find((u) => u.clientId !== reporterClientId);

        if (reporterObj?.dbUserId) reporterId = reporterObj.dbUserId;
        if (reportedObj?.dbUserId) {
            reportedId = reportedObj.dbUserId;
            reportedClientId = reportedObj.clientId;
        }
    }

    if (!reporterId || !reportedId || reporterId === reportedId) {
        return { ok: false, message: 'Rapor baglami cozumlenemedi.' };
    }

    // Fallback path: room/recent context missing olsa bile raporu kaydet.
    if (!conversationId) {
        let fallbackConversationId = conversationIdHint || null;
        if (!fallbackConversationId) {
            try {
                // Legacy/edge fallback: derive a stable conversation context when room state is gone.
                fallbackConversationId = await findOrCreatePersistentConversation(reporterId, reportedId);
            } catch (e) {
                console.warn('Report fallback conversation lookup failed:', {
                    reporterId,
                    reportedId,
                    message: e?.message || e
                });
            }
        }

        const fallback = await logReport(reporterId, reportedId, fallbackConversationId, cleanReason);
        if (fallback?.error) {
            console.error('Report fallback insert failed:', {
                reporterId,
                reportedId,
                conversationId: fallbackConversationId,
                roomId: roomId || null,
                error: fallback.error
            });
            return { ok: false, message: 'Rapor kaydi olusturulamadi.' };
        }
        return {
            ok: true,
            duplicate: !!fallback?.duplicate,
            persisted: !fallback?.duplicate,
            banned: !!fallback?.banned
        };
    }

    // 1. Unique Reporter Check (24h)
    try {
        const existing = await pool.query(
            "SELECT 1 FROM reports WHERE reporter_user_id=$1 AND reported_user_id=$2 AND created_at > NOW() - INTERVAL '24 hours'",
            [reporterId, reportedId]
        );
        if (existing.rows.length > 0) return { ok: true, duplicate: true, persisted: false };
    } catch (e) {
        console.error('Report check error', e);
        return { ok: false, message: 'Rapor kontrolu basarisiz.' };
    }

    // 2. Calculate Weight
    let weight = 1.0;
    try {
        const rUser = await pool.query('SELECT created_at FROM users WHERE id=$1', [reporterId]);
        if (rUser.rows[0]) {
            const ageHours = (Date.now() - new Date(rUser.rows[0].created_at).getTime()) / 3600000;
            if (ageHours < 24) weight = 0.5;
        }
    } catch (e) { }

    const reasonLower = cleanReason.toLowerCase();
    if (['threat', 'hate', 'sexual', 'harassment'].some((r) => reasonLower.includes(r))) weight = 1.5;
    else if (reasonLower.includes('spam') || reasonLower.includes('scam')) weight = 1.0;
    else weight = 0.75;

    // 3. Log Report
    try {
        await pool.query(
            'INSERT INTO reports (reporter_user_id, reported_user_id, conversation_id, reason, meta) VALUES ($1, $2, $3, $4, $5)',
            [reporterId, reportedId, conversationId, cleanReason, JSON.stringify({ weight })]
        );
    } catch (e) {
        console.error('Report insert error', e);
        return { ok: false, message: 'Rapor kaydedilemedi.' };
    }

    // 4. Threshold & Ban Logic
    try {
        // Check 24h Score
        const res24h = await pool.query(`
            SELECT SUM((meta->>'weight')::float) as score, COUNT(DISTINCT reporter_user_id) as reporters
            FROM reports WHERE reported_user_id=$1 AND created_at > NOW() - INTERVAL '24 hours'
        `, [reportedId]);

        const score24h = parseFloat(res24h.rows[0].score || 0);
        const reporters24h = parseInt(res24h.rows[0].reporters || 0, 10);

        if (reporters24h < 2) return { ok: true, persisted: true, banned: false };

        let banHours = 0;

        // Base Scoring
        if (score24h >= 3.0) banHours = 1;
        else if (score24h >= 2.0) banHours = 0.5; // 30 mins

        // Check 7d (Threshold 5)
        if (banHours < 24) {
            const res7d = await pool.query(`SELECT SUM((meta->>'weight')::float) as s FROM reports WHERE reported_user_id=$1 AND created_at > NOW() - INTERVAL '7 days'`, [reportedId]);
            if ((res7d.rows[0].s || 0) >= 5.0) banHours = 24;
        }

        // Check 30d (Threshold 8)
        if (banHours < 168) {
            const res30d = await pool.query(`SELECT SUM((meta->>'weight')::float) as s FROM reports WHERE reported_user_id=$1 AND created_at > NOW() - INTERVAL '30 days'`, [reportedId]);
            if ((res30d.rows[0].s || 0) >= 8.0) banHours = 168; // 7 days
        }

        if (banHours > 0) {
            // 5. Repeat Offender Multiplier
            const history = await pool.query("SELECT COUNT(*) as c FROM bans WHERE user_id=$1 AND created_at > NOW() - INTERVAL '30 days'", [reportedId]);
            const pastBans = parseInt(history.rows[0].c || 0, 10);

            if (pastBans > 0) {
                if (pastBans === 1) banHours = Math.max(banHours, 6);
                else if (pastBans === 2) banHours = Math.max(banHours, 24);
                else if (pastBans === 3) banHours = Math.max(banHours, 168);
                else if (pastBans >= 4) banHours = 87600; // ~10 years (Perma)
            }

            // Apply Ban
            const banUntil = new Date(Date.now() + banHours * 3600000);
            await pool.query(
                'INSERT INTO bans (user_id, ban_type, ban_until, reason, created_by) VALUES ($1, $2, $3, $4, $5)',
                [reportedId, 'system', banUntil, `Auto-Ban: Score ${score24h.toFixed(1)}, History ${pastBans}`, 'auto']
            );

            // Kick User
            const reportTargetClientData = reportedClientId ? activeClients.get(reportedClientId) : null;
            if (reportTargetClientData && reportTargetClientData.ws) {
                sendJson(reportTargetClientData.ws, { type: 'ended', reason: 'banned', message: `Hesabınız geçici olarak askıya alındı. Süre: ${banHours} saat.` });
                reportTargetClientData.ws.close();
            }
            return { ok: true, persisted: true, banned: true };
        }
    } catch (e) {
        console.error('Auto-ban error', e);
    }

    return { ok: true, persisted: true, banned: false };
};

const handleBlock = async (blockerClientId, roomId) => {
    let users = null;
    let roomActive = false;
    const room = rooms.get(roomId); // Only check active room for termination
    if (room) {
        users = room.users;
        roomActive = true;
    } else {
        // Fallback for logging block even if room is gone (from recent)
        const recent = recentRooms.get(roomId);
        if (recent) users = recent.users;
    }

    if (!users) return;

    const blockerObj = users.find(u => u.clientId === blockerClientId);
    const blockedObj = users.find(u => u.clientId !== blockerClientId);

    if (!blockerObj || !blockedObj) return;

    await blockUser(blockerObj.dbUserId, blockedObj.dbUserId);
    console.log(`BLOCK: ${blockerObj.dbUserId} blocked ${blockedObj.dbUserId}`);

    // Terminate chat if active (V6 Fix)
    if (roomActive) {
        leaveRoom(blockerClientId, 'blocked');
    }
};

// Intervals
const interval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, HEARTBEAT_INTERVAL);

// Cache Cleanup
setInterval(() => {
    const now = Date.now();
    for (const [roomId, data] of recentRooms) {
        if (now - data.timestamp > REPORT_TTL) recentRooms.delete(roomId);
    }
    for (const [pairKey, expiresAt] of pairRematchCooldowns) {
        if (Number(expiresAt) <= now) pairRematchCooldowns.delete(pairKey);
    }
}, 60000);

// Serve Frontend Static Files (Production)
app.use(express.static(path.join(__dirname, '../chatapp-frontend/dist')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../chatapp-frontend/dist/index.html'));
});

const startServer = async () => {
    try {
        await ensureTables();
        server.listen(port, () => {
            console.log(`Backend running on ${port}`);
        });
    } catch (error) {
        console.error('Fatal startup error: database initialization failed.', error);
        process.exit(1);
    }
};

startServer();

