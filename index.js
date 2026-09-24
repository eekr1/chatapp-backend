require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { WebSocketServer, WebSocket } = require('ws');
const {
    WS_MAX_PAYLOAD_BYTES,
    isAllowedWebSocketOrigin,
    validateWsEvent
} = require('./utils/wave01Security');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
const { pool, ensureTables, getDatabaseReadiness, closeDatabase } = require('./db');
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
const { buildLegalRelease, calculateLegalStatus, legalStatusPayload } = require('./utils/legalAcceptance');
const { normalizeLang, resolveRequestLang, resolveLangFromHeaders, t } = require('./utils/i18n');
const { sendApiError } = require('./utils/i18n');
const { requestContext } = require('./utils/contracts');
const { BoundedRateLimiter, hashKey, resolvePeerAddress } = require('./utils/abuseProtection');
const { ConnectionRegistry, normalizeClientContext, safeSend } = require('./utils/socketSecurity');
const { findValidSessionByToken, onSessionsRevoked } = require('./utils/sessionService');
const logger = require('./utils/logger');
const { resolveReleaseIdentity, resolveRealtimeRuntimeConfig } = require('./utils/runtimeConfig');
const { createHealthState, createLivenessPayload, createReadinessPayload } = require('./utils/health');
const { RecoveryRegistry, buildRecoverySnapshot } = require('./utils/recoveryState');
const { createPresenceService } = require('./utils/presenceService');
const { onUserRuntimeTermination } = require('./utils/userRuntimeTermination');
const { rebindTransientParticipant, resolveTransientSnapshot } = require('./utils/transientRecovery');
const { createSearchLifecycle } = require('./utils/searchLifecycle');
const {
    assertMatchScopeTopology,
    getFallbackDelayMs,
    matchScopesCapability,
    resolveCanonicalMatchScope
} = require('./utils/matchScope');
const {
    applyDeadline,
    applyDecision,
    closePendingMatch,
    completePendingMatch,
    createPendingMatchRecord,
    markOfferRendered
} = require('./utils/pendingMatch');
const {
    buildDirectMessageAck,
    buildDirectMessageFailure,
    persistDirectMessage,
    resolveDirectConversation,
    validateDirectText
} = require('./utils/directMessage');
const {
    validateImageDataUrl,
    persistDirectImage,
    consumeImage,
    cleanupExpiredMedia
} = require('./utils/mediaLifecycle');
logger.installSafeConsole();

// Global State (Only Transients)
// Connected clients mapping: clientId -> { ws, dbUserId, deviceId, isShadowBanned, nickname }
const activeClients = new Map();
const connectionRegistry = new ConnectionRegistry();
onSessionsRevoked((sessions, reason) => connectionRegistry.closeSessions(sessions, reason));

const app = express();
const port = process.env.PORT || 3000;
const releaseIdentity = resolveReleaseIdentity(process.env);
const realtimeConfig = resolveRealtimeRuntimeConfig(process.env);
const healthState = createHealthState();
const REQUEST_TELEMETRY_SAMPLE_RATE = 0.2;
const REQUEST_TELEMETRY_SLOW_MS = 1500;
const REQUEST_TELEMETRY_EVENTS_RETENTION_DAYS = 7;
const REQUEST_TELEMETRY_METRICS_RETENTION_DAYS = 30;
const REQUEST_TELEMETRY_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const REQUEST_TELEMETRY_CLEANUP_CHANCE = 0.02;
const BEHAVIOR_EVENTS_RETENTION_DAYS = Math.max(7, Math.min(365, Number(process.env.BEHAVIOR_EVENTS_RETENTION_DAYS) || 90));
const BEHAVIOR_EVENTS_CLEANUP_INTERVAL_MS = 4 * 60 * 60 * 1000;
const BEHAVIOR_EVENTS_CLEANUP_CHANCE = 0.01;
const NOTIFICATION_SCHEDULER_INTERVAL_MS = Math.max(10000, Math.min(300000, Number(process.env.NOTIFICATION_SCHEDULER_INTERVAL_MS) || 30000));
const DEFAULT_NOTIFICATION_TIMEZONE = process.env.NOTIFICATION_DEFAULT_TIMEZONE || 'Europe/Istanbul';
const REQUEST_TELEMETRY_STATIC_FILE_RE = /\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|otf|mp4|webm|ogg)$/i;
const UUID_SEGMENT_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/ig;
const NUMERIC_SEGMENT_RE = /\/\d+(?=\/|$)/g;
const requestTelemetryCleanupState = { running: false, lastRunAt: 0 };
const behaviorEventsCleanupState = { running: false, lastRunAt: 0 };
const notificationSchedulerState = { running: false, timer: null };

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
    if (pathName === '/health' || pathName.startsWith('/health/')) return true;
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

const maybeCleanupBehaviorEvents = () => {
    const now = Date.now();
    if (behaviorEventsCleanupState.running) return;
    if (now - behaviorEventsCleanupState.lastRunAt < BEHAVIOR_EVENTS_CLEANUP_INTERVAL_MS) return;
    if (Math.random() > BEHAVIOR_EVENTS_CLEANUP_CHANCE) return;

    behaviorEventsCleanupState.running = true;
    behaviorEventsCleanupState.lastRunAt = now;

    pool.query(
        `DELETE FROM behavior_events
         WHERE created_at < NOW() - ($1::text || ' days')::interval`,
        [BEHAVIOR_EVENTS_RETENTION_DAYS]
    )
        .catch((e) => {
            console.warn('behavior events cleanup failed:', e?.message || e);
        })
        .finally(() => {
            behaviorEventsCleanupState.running = false;
        });
};

const parseScheduleClock = (value) => {
    const match = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(String(value || '').trim());
    if (!match) return null;
    return {
        hour: Number(match[1]),
        minute: Number(match[2])
    };
};

const normalizeScheduleTimezone = (value) => {
    const raw = String(value || '').trim();
    const candidate = raw || DEFAULT_NOTIFICATION_TIMEZONE;
    try {
        new Intl.DateTimeFormat('en-US', { timeZone: candidate }).format(new Date());
        return candidate;
    } catch {
        return DEFAULT_NOTIFICATION_TIMEZONE;
    }
};

const getZonedDateParts = (timeZone, at = new Date()) => {
    const fmt = new Intl.DateTimeFormat('en-CA', {
        timeZone,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });
    const parts = fmt.formatToParts(at);
    const map = {};
    for (const p of parts) {
        if (p.type !== 'literal') map[p.type] = p.value;
    }
    const year = Number(map.year);
    const month = Number(map.month);
    const day = Number(map.day);
    const hour = Number(map.hour);
    const minute = Number(map.minute);
    if ([year, month, day, hour, minute].some((n) => Number.isNaN(n))) return null;
    const monthText = String(month).padStart(2, '0');
    const dayText = String(day).padStart(2, '0');
    return {
        year,
        month,
        day,
        hour,
        minute,
        localDate: `${year}-${monthText}-${dayText}`,
        minutesSinceStartOfDay: (hour * 60) + minute
    };
};

const runNotificationSchedulesTick = async () => {
    if (notificationSchedulerState.running) return;
    if (typeof adminRoutes.sendSystemNotice !== 'function') return;

    notificationSchedulerState.running = true;
    try {
        const schedulesRes = await pool.query(
            `
            SELECT id, title, body, duration_ms, schedule_time, timezone, is_active, last_sent_local_date
            FROM notification_schedules
            WHERE is_active = TRUE
            `
        );

        const now = new Date();
        for (const row of schedulesRes.rows || []) {
            const scheduleClock = parseScheduleClock(row.schedule_time);
            if (!scheduleClock) continue;

            const timeZone = normalizeScheduleTimezone(row.timezone);
            const zonedNow = getZonedDateParts(timeZone, now);
            if (!zonedNow) continue;

            const scheduleMinute = (scheduleClock.hour * 60) + scheduleClock.minute;
            if (zonedNow.minutesSinceStartOfDay < scheduleMinute) continue;
            if (String(row.last_sent_local_date || '') === zonedNow.localDate) continue;

            try {
                await adminRoutes.sendSystemNotice({
                    title: String(row.title || '').trim(),
                    body: String(row.body || '').trim(),
                    durationMs: Math.max(3000, Math.min(60000, Number(row.duration_ms) || 10000)),
                    target: 'all'
                });
                await pool.query(
                    `
                    UPDATE notification_schedules
                    SET
                        last_sent_local_date = $2,
                        last_sent_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $1
                    `,
                    [row.id, zonedNow.localDate]
                );
                trackBehaviorEvent({
                    eventName: 'scheduled_notification_sent',
                    metadata: {
                        schedule_id: row.id,
                        timezone: timeZone,
                        schedule_time: row.schedule_time
                    }
                });
            } catch (e) {
                console.warn('scheduled notice send failed:', row.id, e?.message || e);
            }
        }
    } catch (e) {
        console.warn('notification scheduler tick failed:', e?.message || e);
    } finally {
        notificationSchedulerState.running = false;
    }
};

const startNotificationScheduler = () => {
    if (notificationSchedulerState.timer) {
        clearInterval(notificationSchedulerState.timer);
    }
    notificationSchedulerState.timer = setInterval(() => {
        runNotificationSchedulesTick().catch((e) => {
            console.warn('notification scheduler error:', e?.message || e);
        });
    }, NOTIFICATION_SCHEDULER_INTERVAL_MS);

    setTimeout(() => {
        runNotificationSchedulesTick().catch((e) => {
            console.warn('notification scheduler bootstrap error:', e?.message || e);
        });
    }, 1500);
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
    "http://localhost:5173",
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

app.disable('x-powered-by');
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
});
app.use(requestContext);
app.use(express.json({ limit: '128kb', strict: true }));
app.use((err, req, res, next) => {
    if (err?.type === 'entity.too.large') {
        return sendApiError(req, res, 413, 'PAYLOAD_TOO_LARGE');
    }
    if (err instanceof SyntaxError && err.status === 400 && Object.prototype.hasOwnProperty.call(err, 'body')) {
        return sendApiError(req, res, 400, 'INVALID_JSON');
    }
    return next(err);
});

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
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => [
        hashKey('auth-peer', resolvePeerAddress(req)),
        hashKey('auth-user', String(req.body?.username || '').trim().toLowerCase()),
        hashKey('auth-device', req.body?.device_id || 'unknown')
    ].join(':'),
    handler: (req, res) => {
        const retryAfterMs = Math.max(0, Number(req.rateLimit?.resetTime || 0) - Date.now());
        return sendApiError(req, res, 429, 'RATE_LIMITED', {}, 'errors.RATE_LIMIT', {
            retryable: true, retryAfterMs, metadata: { policy: 'auth' }
        });
    }
});

const apiLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 300, // 300 requests per IP
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        const authorization = String(req.headers.authorization || '').trim();
        return authorization
            ? `session:${hashKey('api-session', authorization)}`
            : `peer:${hashKey('api-peer', resolvePeerAddress(req))}`;
    },
    handler: (req, res) => {
        const retryAfterMs = Math.max(0, Number(req.rateLimit?.resetTime || 0) - Date.now());
        return sendApiError(req, res, 429, 'RATE_LIMITED', {}, 'errors.RATE_LIMIT', {
            retryable: true, retryAfterMs, metadata: { policy: 'public-api' }
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
        const release = buildLegalRelease({ item, updatedAt });
        res.set('Cache-Control', 'public, max-age=300, must-revalidate');
        res.set('ETag', `\"${release.checksum}\"`);
        res.json({
            ...item,
            updatedAt,
            release_id: release.releaseId,
            revision: release.revision,
            checksum: release.checksum,
            published_at: release.publishedAt,
            format: release.format
        });
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

app.get('/health/live', (req, res) => {
    const payload = createLivenessPayload({ release: releaseIdentity, healthState });
    res.status(healthState.shuttingDown ? 503 : 200).json(payload);
});

app.get('/health/ready', async (req, res) => {
    const database = healthState.shuttingDown
        ? { ok: false, code: 'SHUTTING_DOWN' }
        : await getDatabaseReadiness();
    const payload = createReadinessPayload({ release: releaseIdentity, database, healthState });
    res.status(payload.status === 'ready' ? 200 : 503).json(payload);
});

const server = http.createServer(app);
const wss = new WebSocketServer({
    server,
    maxPayload: WS_MAX_PAYLOAD_BYTES,
    verifyClient: ({ origin }) => isAllowedWebSocketOrigin(origin, allowedOrigins)
});

/**
 * Global State (Only Transients)
 * DB handles presistence. Memory only for active connections.
 * 
 * V6 UPDATE: 'username' is now fetched from DB for connected users if available.
 */
let waitingQueue = []; // [{ clientId, ws, nickname, dbUserId, searchId, queueAttempt, queuedAt }]
const rooms = new Map(); // roomId -> { users: [...], sockets: {...}, conversationId: uuid }
const userRoomMap = new Map(); // clientId (socket uuid) -> roomId
const pendingMatches = new Map(); // matchId -> { id, users, autoAcceptAt, timeoutMs, timer, finalized }
const userPendingMatchMap = new Map(); // clientId -> matchId
const pairRematchCooldowns = new Map(); // pairKey -> expiresAt
const recoveryRegistry = new RecoveryRegistry({
    graceMs: realtimeConfig.recoveryGraceMs,
    enabled: realtimeConfig.recoveryEnabled
});
const presenceService = createPresenceService({ pool, config: realtimeConfig });
let presenceCleanupRunning = false;


// Config
const RATE_LIMIT_WINDOW = 1000;
const RATE_LIMIT_MAX = 5;
const REPORT_TTL = 5 * 60 * 1000;
const HEARTBEAT_INTERVAL = 30000;
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
// Recent Rooms for Report fallback (Memory cache)
const recentRooms = new Map();

// Helpers
const REVISION_EVENTS = new Set([
    'queued', 'match_offer', 'match_offer_peer_accepted', 'match_offer_waiting',
    'match_decision_result', 'match_finalizing', 'match_offer_closed', 'search_phase', 'queue_left', 'matched', 'ended', 'presence_update', 'friend_refresh',
    'country_fallback_available', 'country_fallback_ack', 'match_scope_change_failed'
]);
const sendJson = (ws, data) => {
    const lease = recoveryRegistry.getByConnection(ws?.clientId);
    if (!lease) return safeSend(ws, data);
    const stateRevision = REVISION_EVENTS.has(data?.type)
        ? recoveryRegistry.bump(ws.clientId)
        : lease.stateRevision;
    return safeSend(ws, {
        connectionId: ws.clientId,
        serverEpoch: recoveryRegistry.serverEpoch,
        stateRevision,
        ...data
    });
};

const searchLifecycle = createSearchLifecycle({
    fallbackDelayMs: getFallbackDelayMs(process.env),
    onPhase: (record, event) => {
        waitingQueue = waitingQueue.map((item) => item.searchId === record.searchId
            ? { ...item, phase: record.phase, searchRevision: record.revision }
            : item);
        const client = activeClients.get(record.connectionId);
        if (client?.ws?.readyState === WebSocket.OPEN) sendJson(client.ws, event);
    },
    onFallback: (record, event) => {
        waitingQueue = waitingQueue.map((item) => item.searchId === record.searchId
            ? { ...item, fallbackStatus: record.fallbackStatus, searchRevision: record.revision }
            : item);
        const client = activeClients.get(record.connectionId);
        if (client?.ws?.readyState === WebSocket.OPEN) {
            sendJson(client.ws, event);
            trackBehaviorEvent({
                eventName: 'match_country_fallback_shown',
                userId: client.dbUserId,
                clientId: record.connectionId,
                deviceId: client.deviceId || null,
                platform: client.platform || null,
                metadata: {
                    search_id: record.searchId,
                    effective_scope: record.effectiveMatchScope,
                    country_code: record.country?.code || null,
                    queue_attempt: record.queueAttempt
                }
            });
        }
    }
});

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
    sendJson(ws, {
        type: 'error',
        errorCode: code,
        code,
        message: resolvedMessage,
        retryable: code === 'RATE_LIMITED' || code === 'SERVER_ERROR',
        ...extra
    });
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUuid = (value) => typeof value === 'string' && UUID_RE.test(value);
const toText = (value, fallback = '') => (typeof value === 'string' ? value : fallback);
const normalizeAnalyticsPlatform = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'android' || normalized === 'ios' || normalized === 'web') return normalized;
    return 'unknown';
};
const sanitizeBehaviorMetadata = (input) => {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
    const out = {};
    for (const [key, rawValue] of Object.entries(input)) {
        const name = String(key || '').trim();
        if (!name) continue;
        const trimmedName = name.slice(0, 64);
        if (rawValue === null || rawValue === undefined) {
            out[trimmedName] = null;
            continue;
        }
        if (typeof rawValue === 'number' || typeof rawValue === 'boolean') {
            out[trimmedName] = rawValue;
            continue;
        }
        if (typeof rawValue === 'string') {
            out[trimmedName] = rawValue.slice(0, 240);
            continue;
        }
        if (Array.isArray(rawValue)) {
            out[trimmedName] = rawValue.slice(0, 20).map((item) => String(item).slice(0, 120));
            continue;
        }
        out[trimmedName] = String(rawValue).slice(0, 240);
    }
    return out;
};
const trackBehaviorEvent = ({
    eventName,
    userId = null,
    clientId = null,
    deviceId = null,
    platform = null,
    matchId = null,
    conversationId = null,
    metadata = {}
} = {}) => {
    const cleanEventName = String(eventName || '').trim().toLowerCase().slice(0, 80);
    if (!cleanEventName) return;

    const cleanUserId = isUuid(userId) ? userId : null;
    const cleanMatchId = isUuid(matchId) ? matchId : null;
    const cleanConversationId = isUuid(conversationId) ? conversationId : null;
    const cleanClientId = String(clientId || '').trim().slice(0, 120) || null;
    const cleanDeviceId = String(deviceId || '').trim().slice(0, 200) || null;
    const cleanPlatform = normalizeAnalyticsPlatform(platform);
    const cleanMetadata = sanitizeBehaviorMetadata(metadata);

    pool.query(
        `INSERT INTO behavior_events
          (event_name, user_id, client_id, device_id, platform, match_id, conversation_id, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW())`,
        [
            cleanEventName,
            cleanUserId,
            cleanClientId,
            cleanDeviceId,
            cleanPlatform,
            cleanMatchId,
            cleanConversationId,
            JSON.stringify(cleanMetadata)
        ]
    ).catch((e) => {
        console.warn('behavior event insert failed:', cleanEventName, e?.message || e);
    });

    maybeCleanupBehaviorEvents();
};
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

adminRoutes.getOnlineUsersSnapshot = () => {
    const items = [];
    for (const [clientId, client] of activeClients) {
        if (!client || !client.ws || client.ws.readyState !== WebSocket.OPEN) continue;
        items.push({
            clientId,
            dbUserId: client.dbUserId || null,
            username: client.username || null,
            nickname: client.nickname || null,
            deviceId: client.deviceId || null,
            platform: client.platform || null,
            lang: client.lang || null,
            connectedAt: client.connectedAt || null
        });
    }
    return items;
};

adminRoutes.getActiveConversationCount = () => {
    let count = 0;
    for (const [, room] of rooms) {
        if (!room || !Array.isArray(room.users) || room.users.length < 2) continue;
        const [a, b] = room.users;
        const wsA = room.sockets?.[a?.clientId];
        const wsB = room.sockets?.[b?.clientId];
        if (wsA?.readyState === WebSocket.OPEN && wsB?.readyState === WebSocket.OPEN) {
            count++;
        }
    }
    return count;
};

const WS_EVENT_COST = Object.freeze({ message: 2, direct_message: 2, image_send: 5, direct_image_send: 5, report: 5, joinQueue: 2 });
const wsAbuseLimiter = new BoundedRateLimiter({ windowMs: RATE_LIMIT_WINDOW, max: RATE_LIMIT_MAX * 4, maxKeys: 20000 });

function heartbeat() { this.isAlive = true; }

const broadcastOnlineCount = () => {
    const count = wss.clients.size;
    const msg = JSON.stringify({ type: 'onlineCount', count });
    wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
};

const cleanupEphemeralMedia = async () => {
    try {
        const result = await cleanupExpiredMedia({ pool, dryRun: process.env.MEDIA_CLEANUP_EXECUTE !== 'true' });
        if (result.affected) console.info('ephemeral_media cleanup', result);
    } catch (e) {
        // Non-fatal. Table may not be ready on cold start.
        console.warn('ephemeral_media cleanup failed:', e.message);
    }
};

cleanupEphemeralMedia();
setInterval(cleanupEphemeralMedia, 6 * 60 * 60 * 1000); // every 6 hours

// --- DB Logic Helpers ---

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

async function resolveReportSubject(reportedId, conversationId, messageId, mediaId) {
    if (!reportedId || !conversationId || (!messageId && !mediaId)) return { messageId: null, mediaId: null, mediaStatus: null };
    const result = await pool.query(
        `SELECT m.id,m.media_id,em.status AS media_status
         FROM messages m LEFT JOIN ephemeral_media em ON em.id=m.media_id
         WHERE m.conversation_id=$1 AND m.sender_id=$2
           AND (($3::uuid IS NOT NULL AND m.id=$3::uuid) OR ($4::uuid IS NOT NULL AND m.media_id=$4::uuid))
         LIMIT 1`,
        [conversationId, reportedId, messageId || null, mediaId || null]
    );
    const row = result.rows[0];
    return row
        ? { messageId: row.id, mediaId: row.media_id || null, mediaStatus: row.media_status || null }
        : { messageId: null, mediaId: null, mediaStatus: null };
}

async function auditAutomaticBan({ reportedId, banHours, source, score = null, reporterCount = null }) {
    try {
        await pool.query(
            `INSERT INTO admin_action_audit
              (actor_admin, action_type, entity_type, entity_id, payload)
             VALUES ('system', 'auto_ban', 'user', $1, $2::jsonb)`,
            [reportedId, JSON.stringify({ source, ban_hours: banHours, score, reporter_count: reporterCount, policy_version: 'wave11-v1' })]
        );
    } catch (error) {
        console.error('Auto-ban audit insert failed:', { reportedId, source, code: error?.code || 'AUDIT_INSERT_FAILED' });
    }
}

async function logReport(reporterId, reportedId, conversationId, reason, evidence = {}) {
    const cleanReason = String(reason || '').trim().slice(0, 800);
    const cleanConversationId = conversationId || null;
    if (!reporterId || !reportedId || !cleanReason) {
        return { error: 'invalid_input' };
    }
    if (reporterId === reportedId) {
        return { error: 'self_report_not_allowed' };
    }
    try {
        const subject = await resolveReportSubject(reportedId, cleanConversationId, evidence.messageId, evidence.mediaId);
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
            `INSERT INTO reports
              (reporter_user_id,reported_user_id,conversation_id,reason,command_id,reason_category,subject_message_id,subject_media_id,evidence_availability,moderation_status,protocol_version,meta)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'metadata_only','received','wave11-v1',$9)
             ON CONFLICT (reporter_user_id,command_id) WHERE command_id IS NOT NULL DO NOTHING`,
            [reporterId, reportedId, cleanConversationId, cleanReason, evidence.commandId || null,
                evidence.reasonCategory || 'other', subject.messageId, subject.mediaId,
                JSON.stringify({ evidence_policy: 'metadata_only', content_retained: false, media_status: subject.mediaStatus })]
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
            await auditAutomaticBan({ reportedId, banHours: 24, source: 'report_fallback_threshold', reporterCount: parseInt(reports24h.rows[0].cnt, 10) });
            return { banned: true };
        }

        return { banned: false };

    } catch (e) {
        console.error('DB Error logReport:', e);
        return { error: e?.message || 'db_error' };
    }
}

async function createConversationForMatch(matchId, userAId, userBId) {
    const newId = uuidv4();
    const result = await pool.query(
        `INSERT INTO conversations (id, user_a_id, user_b_id, match_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (match_id) WHERE match_id IS NOT NULL
         DO UPDATE SET match_id = EXCLUDED.match_id
         RETURNING id`,
        [newId, userAId, userBId, matchId]
    );
    return result.rows[0].id;
}


// --- Main Logic ---

const removeFromQueue = (clientId) => {
    waitingQueue = waitingQueue.filter(item => item.clientId !== clientId);
};

const createRoom = (roomId, conversationId, userA, userB, matchId = null, trigger = 'manual') => {
    rooms.set(roomId, {
        users: [
            { clientId: userA.clientId, nickname: userA.nickname, username: userA.username, dbUserId: userA.dbUserId },
            { clientId: userB.clientId, nickname: userB.nickname, username: userB.username, dbUserId: userB.dbUserId }
        ],
        sockets: {
            [userA.clientId]: userA.ws,
            [userB.clientId]: userB.ws
        },
        conversationId: conversationId,
        matchId
    });

    userRoomMap.set(userA.clientId, roomId);
    userRoomMap.set(userB.clientId, roomId);

    sendJson(userA.ws, { type: 'matched', matchId, roomId, searchId: userA.searchId, queueAttempt: userA.queueAttempt, searchRevision: userA.searchRevision, effectiveMatchScope: userA.effectiveMatchScope, country: userA.country, peerNickname: userB.nickname, peerUsername: userB.username, peerId: userB.dbUserId }); // V13: add peerId
    sendJson(userB.ws, { type: 'matched', matchId, roomId, searchId: userB.searchId, queueAttempt: userB.queueAttempt, searchRevision: userB.searchRevision, effectiveMatchScope: userB.effectiveMatchScope, country: userB.country, peerNickname: userA.nickname, peerUsername: userA.username, peerId: userA.dbUserId });

    trackBehaviorEvent({
        eventName: 'chat_started',
        userId: userA.dbUserId,
        clientId: userA.clientId,
        deviceId: userA.deviceId || null,
        platform: userA.platform || null,
        matchId,
        conversationId,
        metadata: {
            peer_user_id: userB.dbUserId || null,
            trigger,
            effective_scope: userA.effectiveMatchScope,
            country_code: userA.country?.code || null,
            search_id: userA.searchId
        }
    });
    trackBehaviorEvent({
        eventName: 'chat_started',
        userId: userB.dbUserId,
        clientId: userB.clientId,
        deviceId: userB.deviceId || null,
        platform: userB.platform || null,
        matchId,
        conversationId,
        metadata: {
            peer_user_id: userA.dbUserId || null,
            trigger,
            effective_scope: userB.effectiveMatchScope,
            country_code: userB.country?.code || null,
            search_id: userB.searchId
        }
    });
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

const pendingEvent = (pending, participant, type, extra = {}) => ({
    type,
    protocolVersion: 1,
    matchId: pending.id,
    matchRevision: pending.revision,
    matchStatus: pending.status,
    searchId: participant.searchId,
    queueAttempt: participant.queueAttempt,
    searchRevision: participant.searchRevision,
    effectiveMatchScope: participant.effectiveMatchScope,
    country: participant.country,
    offeredAt: pending.offeredAt,
    autoAcceptAt: pending.autoAcceptAt,
    timingPolicyVersion: 'pending-match-timing-v1',
    serverNow: new Date().toISOString(),
    ...extra
});

const clearPendingMatchById = (matchId) => {
    const pending = pendingMatches.get(matchId);
    if (!pending) return null;
    if (pending.timer) clearTimeout(pending.timer);
    pendingMatches.delete(matchId);
    pending.users.forEach((u) => userPendingMatchMap.delete(u.clientId));
    return pending;
};

const queueClientForRematch = (clientId, trigger = 'auto_requeue') => {
    setTimeout(() => {
        const clientData = activeClients.get(clientId);
        if (!clientData?.ws || clientData.ws.readyState !== WebSocket.OPEN) return;
        joinQueue(clientData.ws, { trigger, requeue: true }).catch((e) => {
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
    const pending = pendingMatches.get(matchId);
    if (!pending) return false;
    const transition = pending.status === 'closed'
        ? { kind: 'closed' }
        : closePendingMatch(pending, actorReason || peerReason || 'cancelled', {
            allowFinalizing: pending.status === 'finalizing' && !pending.finalizationPromise
        });
    if (transition.kind !== 'closed') return false;
    clearPendingMatchById(matchId);

    pending.users.forEach((participant) => {
        const ws = activeClients.get(participant.clientId)?.ws || participant.ws;
        if (!ws || ws.readyState !== WebSocket.OPEN) return;

        const isActor = actorClientId && participant.clientId === actorClientId;
        const reason = isActor ? actorReason : peerReason;
        if (!reason) return;

        sendJson(ws, pendingEvent(pending, participant, 'match_offer_closed', { reason }));
        trackBehaviorEvent({
            eventName: 'match_offer_closed',
            userId: participant.dbUserId,
            clientId: participant.clientId,
            deviceId: activeClients.get(participant.clientId)?.deviceId || null,
            platform: activeClients.get(participant.clientId)?.platform || null,
            matchId,
            metadata: {
                event_version: 1,
                search_id: participant.searchId,
                effective_scope: participant.effectiveMatchScope,
                reason
            }
        });
    });

    pending.users.forEach((participant) => {
        const isActor = actorClientId && participant.clientId === actorClientId;
        const shouldRequeue = isActor ? requeueActor : requeuePeers;
        if (shouldRequeue) queueClientForRematch(participant.clientId, 'peer_requeue');
    });

    return true;
};

const cancelPendingMatchForClient = (clientId, options = {}) => {
    const context = getPendingMatchForClient(clientId);
    if (!context) return false;
    return cancelPendingMatchById(context.matchId, { actorClientId: clientId, ...options });
};

const finalizePendingMatchIfReady = (matchId, options = {}) => {
    const trigger = String(options?.trigger || 'manual').trim() || 'manual';
    const pending = pendingMatches.get(matchId);
    if (!pending || pending.status !== 'finalizing') return Promise.resolve(false);
    if (pending.finalizationPromise) return pending.finalizationPromise;

    const waitingForRecovery = pending.users.some((participant) => {
        const live = activeClients.get(participant.clientId);
        if (live?.ws?.readyState === WebSocket.OPEN) return false;
        return Boolean(recoveryRegistry.getByConnection(participant.clientId)?.detached);
    });
    if (waitingForRecovery) return Promise.resolve(false);

    pending.finalizationPromise = (async () => {
        const participants = pending.users.map((participant) => {
            const live = activeClients.get(participant.clientId);
            if (!live?.ws || live.ws.readyState !== WebSocket.OPEN) return null;
            return {
                clientId: participant.clientId,
                ws: live.ws,
                nickname: live.nickname || participant.nickname,
                username: live.username || participant.username,
                dbUserId: live.dbUserId || participant.dbUserId,
                deviceId: live.deviceId || null,
                platform: live.platform || null,
                searchId: participant.searchId,
                queueAttempt: participant.queueAttempt,
                searchRevision: participant.searchRevision,
                effectiveMatchScope: participant.effectiveMatchScope,
                country: participant.country
            };
        }).filter(Boolean);

        if (participants.length !== 2) {
            closePendingMatch(pending, 'participant_unavailable', { allowFinalizing: true });
            pending.users.forEach((participant) => {
                const live = activeClients.get(participant.clientId);
                if (live?.ws?.readyState === WebSocket.OPEN) {
                    sendJson(live.ws, pendingEvent(pending, participant, 'match_offer_closed', { reason: 'peer_unavailable' }));
                }
            });
            clearPendingMatchById(matchId);
            participants.forEach((participant) => queueClientForRematch(participant.clientId, 'match_finalize_retry'));
            return false;
        }

        pending.users.forEach((participant) => {
            const client = activeClients.get(participant.clientId);
            if (client?.ws?.readyState === WebSocket.OPEN) {
                sendJson(client.ws, pendingEvent(pending, participant, 'match_finalizing'));
            }
        });
        trackBehaviorEvent({
            eventName: 'match_finalization_started',
            matchId,
            metadata: { event_version: 1, trigger }
        });

        let conversationId = null;
        try {
            conversationId = await createConversationForMatch(matchId, participants[0].dbUserId, participants[1].dbUserId);
        } catch (e) {
            closePendingMatch(pending, 'conversation_error', { allowFinalizing: true });
            clearPendingMatchById(matchId);
            participants.forEach((participant) => {
                sendJson(participant.ws, pendingEvent(pending, participant, 'match_offer_closed', { reason: 'conversation_error' }));
                queueClientForRematch(participant.clientId, 'conversation_error_requeue');
            });
            trackBehaviorEvent({
                eventName: 'match_finalization_result',
                matchId,
                metadata: { event_version: 1, trigger, result: 'conversation_error' }
            });
            return false;
        }

        completePendingMatch(pending, { conversationId });
        const roomId = uuidv4();
        createRoom(roomId, conversationId, participants[0], participants[1], matchId, trigger);
        clearPendingMatchById(matchId);
        participants.forEach((participant) => searchLifecycle.terminate(participant.clientId, 'matched'));
        trackBehaviorEvent({
            eventName: 'match_finalization_result',
            matchId,
            conversationId,
            metadata: { event_version: 1, trigger, result: 'completed' }
        });
        return true;
    })();
    return pending.finalizationPromise;
};

const createPendingMatch = (userA, userB) => {
    const matchId = uuidv4();
    const offeredAt = Date.now();
    const autoAcceptAt = offeredAt + MATCH_CONFIRM_TIMEOUT_MS;
    const userAOffer = searchLifecycle.markOffer(userA.clientId);
    const userBOffer = searchLifecycle.markOffer(userB.clientId);
    if (!userAOffer || !userBOffer) {
        [[userA, userAOffer], [userB, userBOffer]].forEach(([user, offer]) => {
            if (!offer) return;
            const restored = searchLifecycle.requeue({ connectionId: user.clientId });
            if (restored && user.ws?.readyState === WebSocket.OPEN) sendJson(user.ws, restored.event);
        });
        return null;
    }
    const pending = createPendingMatchRecord({
        id: matchId,
        offeredAt,
        autoAcceptAt,
        timeoutMs: MATCH_CONFIRM_TIMEOUT_MS,
        participants: [
            {
                clientId: userA.clientId,
                ws: userA.ws,
                nickname: userA.nickname,
                username: userA.username,
                dbUserId: userA.dbUserId,
                searchId: userAOffer.searchId,
                queueAttempt: userAOffer.queueAttempt,
                searchRevision: userAOffer.searchRevision,
                effectiveMatchScope: userAOffer.effectiveMatchScope,
                country: userAOffer.country
            },
            {
                clientId: userB.clientId,
                ws: userB.ws,
                nickname: userB.nickname,
                username: userB.username,
                dbUserId: userB.dbUserId,
                searchId: userBOffer.searchId,
                queueAttempt: userBOffer.queueAttempt,
                searchRevision: userBOffer.searchRevision,
                effectiveMatchScope: userBOffer.effectiveMatchScope,
                country: userBOffer.country
            }
        ]
    });

    pendingMatches.set(matchId, pending);
    pending.users.forEach((participant) => userPendingMatchMap.set(participant.clientId, matchId));

    pending.users.forEach((participant) => {
        const peer = pending.users.find((u) => u.clientId !== participant.clientId);
        if (!peer || participant.ws.readyState !== WebSocket.OPEN) return;
        const peerPublicLabel = String(peer.username || peer.nickname || '').trim().slice(0, 40) || 'Anonymous';
        sendJson(participant.ws, pendingEvent(pending, participant, 'match_offer', {
            peerPublicLabel,
            timeoutMs: MATCH_CONFIRM_TIMEOUT_MS
        }));
        trackBehaviorEvent({
            eventName: 'match_offer_received',
            userId: participant.dbUserId,
            clientId: participant.clientId,
            deviceId: activeClients.get(participant.clientId)?.deviceId || null,
            platform: activeClients.get(participant.clientId)?.platform || null,
            matchId,
            metadata: {
                timeout_ms: MATCH_CONFIRM_TIMEOUT_MS,
                search_id: participant.searchId,
                queue_attempt: participant.queueAttempt,
                effective_scope: participant.effectiveMatchScope,
                country_code: participant.country?.code || null,
                wait_ms: Math.max(0, Date.now() - new Date(searchLifecycle.getByConnection(participant.clientId)?.queuedAt || Date.now()).getTime())
            }
        });
    });

    pending.timer = setTimeout(() => {
        const current = pendingMatches.get(matchId);
        if (!current) return;
        const deadline = applyDeadline(current);
        deadline.changed.forEach((participant) => {
            const live = activeClients.get(participant.clientId);
            trackBehaviorEvent({
                eventName: 'match_auto_accept_applied',
                userId: participant.dbUserId,
                clientId: participant.clientId,
                deviceId: live?.deviceId || null,
                platform: live?.platform || null,
                matchId,
                metadata: { event_version: 1, timeout_ms: MATCH_CONFIRM_TIMEOUT_MS, search_id: participant.searchId }
            });
            if (live?.ws?.readyState === WebSocket.OPEN) {
                sendJson(live.ws, pendingEvent(current, participant, 'match_decision_result', {
                    decision: 'accept',
                    decisionSource: 'auto',
                    result: 'accepted'
                }));
            }
        });
        finalizePendingMatchIfReady(matchId, { trigger: 'auto_accept' }).catch((e) => {
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

const applyMatchDecision = async (ws, providedMatchId, decision, identity = {}) => {
    const context = getPendingMatchForClient(ws.clientId);
    if (!context) return sendError(ws, 'STALE_MATCH');

    const { matchId, pending, participantIndex } = context;
    if (providedMatchId && providedMatchId !== matchId) {
        return sendError(ws, 'STALE_MATCH');
    }

    const participant = pending.users[participantIndex];
    if (!participant) return;

    const actor = activeClients.get(ws.clientId);
    const normalizedDecision = decision === 'reject' ? 'pass' : decision;
    const commandId = identity.commandId || `legacy:${ws.clientId}:${matchId}:${normalizedDecision}`;
    const providedSearchId = identity.searchId || participant.searchId;
    const outcome = applyDecision(pending, {
        participantId: ws.clientId,
        decision: normalizedDecision,
        commandId,
        searchId: providedSearchId
    });
    sendJson(ws, pendingEvent(pending, participant, 'match_decision_result', {
        commandId,
        decision: normalizedDecision,
        result: outcome.kind,
        decisionSource: 'manual',
        replayed: Boolean(outcome.replayed)
    }));
    if (outcome.replayed || ['stale', 'conflict', 'terminal', 'already_decided'].includes(outcome.kind)) return outcome;

    trackBehaviorEvent({
        eventName: 'match_decision_submitted',
        userId: participant.dbUserId,
        clientId: ws.clientId,
        deviceId: actor?.deviceId || null,
        platform: actor?.platform || null,
        matchId,
        metadata: {
            event_version: 1,
            decision: normalizedDecision,
            command_id: commandId,
            search_id: participant.searchId,
            effective_scope: participant.effectiveMatchScope
        }
    });
    trackBehaviorEvent({
        eventName: 'match_decision_result',
        userId: participant.dbUserId,
        clientId: ws.clientId,
        deviceId: actor?.deviceId || null,
        platform: actor?.platform || null,
        matchId,
        metadata: { event_version: 1, decision: normalizedDecision, result: outcome.kind }
    });

    if (normalizedDecision === 'accept') {
        const peer = pending.users.find((u) => u.clientId !== ws.clientId);
        if (peer && peer.decision === 'pending') {
            const peerWs = activeClients.get(peer.clientId)?.ws || peer.ws;
            if (peerWs && peerWs.readyState === WebSocket.OPEN) {
                sendJson(peerWs, pendingEvent(pending, peer, 'match_offer_peer_accepted'));
            }
        }
        if (outcome.kind === 'finalize') await finalizePendingMatchIfReady(matchId, { trigger: 'manual_accept' });
        return outcome;
    }

    const first = pending.users[0] || null;
    const second = pending.users[1] || null;
    if (first?.dbUserId && second?.dbUserId) {
        setPairRematchCooldown(first.dbUserId, second.dbUserId);
    }
    cancelPendingMatchById(matchId, {
        actorClientId: ws.clientId,
        actorReason: 'self_passed',
        peerReason: 'peer_passed',
        requeueActor: true,
        requeuePeers: true
    });
    return outcome;
};

const joinQueue = async (ws, options = {}) => {
    const trigger = String(options?.trigger || 'manual').trim() || 'manual';
    const clientData = activeClients.get(ws.clientId);
    if (!clientData || !clientData.dbUserId) return sendError(ws, 'AUTH_ERROR');

    // Require nickname (V6)
    if (!clientData.nickname) {
        return sendError(ws, 'NO_NICKNAME');
    }

    let scopeContext = null;
    if (!options.requeue) {
        try {
            scopeContext = await resolveCanonicalMatchScope({
                pool,
                userId: clientData.dbUserId,
                requestedScope: options.scope || 'GLOBAL',
                locale: resolveWsLang(ws)
            });
        } catch (error) {
            console.warn('match scope resolution failed', { code: error?.code || 'MATCH_SCOPE_LOOKUP_FAILED' });
            return sendError(ws, 'SERVER_ERROR');
        }
        if (!scopeContext.ok) {
            return sendJson(ws, {
                type: options.replaceFrom ? 'match_scope_change_failed' : 'search_error',
                protocolVersion: 1,
                searchId: options.searchId || null,
                commandId: options.commandId || null,
                errorCode: scopeContext.code,
                code: scopeContext.code,
                retryable: false,
                requestedScope: scopeContext.requestedScope,
                serverNow: new Date().toISOString()
            });
        }
    }

    let lifecycleResult;
    if (options.requeue) {
        const requeued = searchLifecycle.requeue({ connectionId: ws.clientId });
        if (!requeued) return sendError(ws, 'SEARCH_NOT_ACTIVE');
        lifecycleResult = { kind: 'accepted', ...requeued };
    } else if (options.replaceFrom) {
        lifecycleResult = searchLifecycle.replace({
            userId: clientData.dbUserId,
            connectionId: ws.clientId,
            fromSearchId: options.replaceFrom,
            searchId: options.searchId,
            commandId: options.commandId,
            scopeContext
        });
    } else {
        lifecycleResult = searchLifecycle.begin({
            userId: clientData.dbUserId,
            connectionId: ws.clientId,
            searchId: options.searchId,
            commandId: options.commandId,
            scopeContext
        });
    }
    sendJson(ws, lifecycleResult.event);
    if (lifecycleResult.kind === 'conflict' || lifecycleResult.kind === 'replay' || lifecycleResult.kind === 'stale') return lifecycleResult;
    const searchRecord = lifecycleResult.record;
    const isCurrentQueueSearch = () => {
        const current = searchLifecycle.getByConnection(ws.clientId);
        return current === searchRecord && ['queued', 'extended'].includes(current.phase);
    };

    if (!options.requeue) {
        trackBehaviorEvent({
            eventName: 'match_scope_selected',
            userId: clientData.dbUserId,
            clientId: ws.clientId,
            deviceId: clientData.deviceId || null,
            platform: clientData.platform || null,
            metadata: {
                event_version: 1,
                search_id: searchRecord.searchId,
                requested_scope: searchRecord.requestedScope,
                effective_scope: searchRecord.effectiveMatchScope,
                country_code: searchRecord.country?.code || null,
                trigger
            }
        });
    }
    trackBehaviorEvent({
        eventName: 'match_search_started',
        userId: clientData.dbUserId,
        clientId: ws.clientId,
        deviceId: clientData.deviceId || null,
        platform: clientData.platform || null,
        metadata: {
            trigger,
            search_id: searchRecord.searchId,
            queue_attempt: searchRecord.queueAttempt,
            requested_scope: searchRecord.requestedScope
        }
    });
    trackBehaviorEvent({
        eventName: 'match_queue_confirmed',
        userId: clientData.dbUserId,
        clientId: ws.clientId,
        deviceId: clientData.deviceId || null,
        platform: clientData.platform || null,
        metadata: {
            trigger,
            search_id: searchRecord.searchId,
            queue_attempt: searchRecord.queueAttempt,
            effective_scope: searchRecord.effectiveMatchScope,
            country_code: searchRecord.country?.code || null
        }
    });

    // Ban Check
    const ban = await checkBan(clientData.dbUserId);
    if (!isCurrentQueueSearch()) return lifecycleResult;
    if (ban) {
        if (ban.ban_type === 'shadow') {
            return lifecycleResult;
        }
        searchLifecycle.terminate(ws.clientId, 'banned');
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
        dbUserId: clientData.dbUserId,
        searchId: searchRecord.searchId,
        queueAttempt: searchRecord.queueAttempt,
        searchStartedAt: searchRecord.searchStartedAt,
        queuedAt: searchRecord.queuedAt,
        phase: searchRecord.phase,
        searchRevision: searchRecord.revision,
        requestedScope: searchRecord.requestedScope,
        effectiveMatchScope: searchRecord.effectiveMatchScope,
        country: searchRecord.country,
        queueKey: searchRecord.queueKey,
        scopePolicyVersion: searchRecord.scopePolicyVersion,
        fallbackEligibleAt: searchRecord.fallbackEligibleAt,
        fallbackStatus: searchRecord.fallbackStatus
    };

    if (waitingQueue.length > 0) {
        let peerIndex = -1;
        let peer = null;

        for (let i = 0; i < waitingQueue.length; i++) {
            const p = waitingQueue[i];
            if (!p || p.clientId === me.clientId || p.queueKey !== me.queueKey) continue;

            const blocked = await checkBlock(me.dbUserId, p.dbUserId);
            if (!isCurrentQueueSearch()) return lifecycleResult;
            if (!blocked && !isPairOnRematchCooldown(me.dbUserId, p.dbUserId)) {
                peerIndex = i;
                peer = p;
                break;
            }
        }

        if (peer && peerIndex !== -1) {
            const peerSearch = searchLifecycle.getByConnection(peer.clientId);
            if (!peerSearch || peerSearch.searchId !== peer.searchId || !['queued', 'extended'].includes(peerSearch.phase)) {
                waitingQueue = waitingQueue.filter((item) => item.clientId !== peer.clientId);
                waitingQueue.push(me);
                return lifecycleResult;
            }
            const currentPeerIndex = waitingQueue.findIndex((item) => item.clientId === peer.clientId && item.searchId === peer.searchId);
            if (currentPeerIndex < 0) {
                waitingQueue.push(me);
                return lifecycleResult;
            }
            waitingQueue.splice(currentPeerIndex, 1);
            createPendingMatch(me, peer);
        } else {
            waitingQueue.push(me);
        }
    } else {
        waitingQueue.push(me);
    }
    return lifecycleResult;
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
            const live = activeClients.get(id);
            trackBehaviorEvent({
                eventName: 'chat_ended',
                userId: u.dbUserId || live?.dbUserId || null,
                clientId: id,
                deviceId: live?.deviceId || null,
                platform: live?.platform || null,
                conversationId: room.conversationId || null,
                metadata: {
                    reason: id === clientId ? reason : 'peer_left',
                    room_id: roomId
                }
            });
            userRoomMap.delete(id);
        });
        rooms.delete(roomId);
    } else {
        userRoomMap.delete(clientId);
    }
};


const rebindTransientState = (previousConnectionId, connectionId, ws) => {
    if (!previousConnectionId || previousConnectionId === connectionId) return;
    waitingQueue = rebindTransientParticipant({
        previousConnectionId, connectionId, ws, waitingQueue,
        pendingMatches, userPendingMatchMap, rooms, userRoomMap
    });
    activeClients.delete(previousConnectionId);
    searchLifecycle.rebind(previousConnectionId, connectionId);
};

onUserRuntimeTermination(async ({ userId, reason }) => {
    const targets = [...activeClients.entries()]
        .filter(([, client]) => String(client?.dbUserId) === String(userId));
    for (const [clientId, client] of targets) {
        cancelPendingMatchForClient(clientId, {
            actorReason: null,
            peerReason: 'peer_unavailable',
            requeueActor: false,
            requeuePeers: true
        });
        removeFromQueue(clientId);
        leaveRoom(clientId, reason);
        searchLifecycle.terminate(clientId, reason);
        const lease = recoveryRegistry.getByConnection(clientId);
        if (lease) recoveryRegistry.expire(lease.token, reason);
        await presenceService.closeFinal(clientId).catch(() => null);
        activeClients.delete(clientId);
        if (client?.ws?.readyState === WebSocket.OPEN) client.ws.close(1008, reason);
    }
    broadcastOnlineCount();
    return { userId, terminatedConnections: targets.length };
});

const buildActiveRecoveryState = (connectionId) => resolveTransientSnapshot({
    connectionId, waitingQueue, pendingMatches, userPendingMatchMap,
    rooms, userRoomMap, activeClients
});

const loadUnreadSnapshot = async (userId) => {
    const result = await pool.query(`
        SELECT m.sender_id AS user_id, COUNT(*)::int AS count
        FROM messages m
        JOIN conversations c ON c.id = m.conversation_id
        WHERE m.sender_id != $1 AND m.is_read = FALSE
          AND (c.user_a_id = $1 OR c.user_b_id = $1)
        GROUP BY m.sender_id
    `, [userId]);
    return {
        friends: result.rows.map((row) => ({ userId: row.user_id, count: Number(row.count) || 0 })),
        system: 0,
        revision: Date.now()
    };
};

const broadcastPresence = async (userId, presence, lastSeenAt = null) => {
    const observedAt = new Date().toISOString();
    try {
        const result = await pool.query(`
            SELECT CASE WHEN user_id = $1 THEN friend_user_id ELSE user_id END AS friend_id
            FROM friendships
            WHERE status = 'accepted' AND (user_id = $1 OR friend_user_id = $1)
              AND NOT EXISTS (
                  SELECT 1 FROM blocks b
                  WHERE (b.blocker_id = $1 AND b.blocked_id = CASE WHEN friendships.user_id = $1 THEN friendships.friend_user_id ELSE friendships.user_id END)
                     OR (b.blocked_id = $1 AND b.blocker_id = CASE WHEN friendships.user_id = $1 THEN friendships.friend_user_id ELSE friendships.user_id END)
              )
        `, [userId]);
        const recipients = new Set(result.rows.map((row) => row.friend_id));
        for (const [, client] of activeClients) {
            if (!recipients.has(client.dbUserId)) continue;
            sendJson(client.ws, { type: 'presence_update', userId, presence, lastSeenAt: presence === 'offline' ? lastSeenAt : null, observedAt });
        }
    } catch (error) {
        console.warn('presence fan-out failed', { code: error?.code || 'PRESENCE_FANOUT_FAILED' });
    }
};

wss.on('connection', (ws, req) => {
    ws.clientId = uuidv4();
    ws.isAlive = true;
    ws.recoveryReady = false;
    ws.limiter = new BoundedRateLimiter({ windowMs: RATE_LIMIT_WINDOW, max: RATE_LIMIT_MAX * 2, maxKeys: 2 });
    ws.prefLang = resolveLangFromHeaders(req.headers || {});
    connectionRegistry.connect(ws, ws.clientId);
    ws.on('pong', function onPong() {
        heartbeat.call(this);
        if (recoveryRegistry.isCurrentConnection(ws.clientId)) {
            presenceService.heartbeat(ws.clientId).catch((error) => {
                console.warn('presence heartbeat failed', { code: error?.code || 'PRESENCE_HEARTBEAT_FAILED' });
            });
        }
    });

    broadcastOnlineCount();
    sendJson(ws, { type: 'hello', clientId: ws.clientId });

    ws.on('message', async (raw) => {
        let data;
        try {
            data = JSON.parse(raw);
        } catch {
            sendError(ws, 'INVALID_JSON');
            return;
        }

        const validation = validateWsEvent(data);
        if (!validation.ok) {
            const isHandshake = data && data.type === 'hello_ack';
            const isDirectMessage = data && data.type === 'direct_message';
            sendError(ws, isHandshake ? 'AUTH_ERROR' : (isDirectMessage ? 'MESSAGE_INVALID' : validation.code), null, {
                ...(isDirectMessage && data.clientMsgId ? { clientMsgId: data.clientMsgId, retryable: false } : {})
            });
            if (isHandshake) ws.close(1008, 'Authentication required');
            return;
        }

        const eventCost = WS_EVENT_COST[data.type] || 1;
        const localRate = ws.limiter.consume('events', eventCost);
        const currentClient = activeClients.get(ws.clientId);
        const actorKey = currentClient
            ? `actor:${hashKey('ws-actor', `${currentClient.dbUserId}:${currentClient.deviceId}`)}`
            : `peer:${hashKey('ws-peer', resolvePeerAddress(req))}`;
        const actorRate = wsAbuseLimiter.consume(actorKey, eventCost);
        if (!localRate.allowed || !actorRate.allowed) {
            const retryAfterMs = Math.max(localRate.retryAfterMs, actorRate.retryAfterMs);
            sendError(ws, 'RATE_LIMITED', null, {
                retryAfterMs,
                policy: 'ws-event',
                ...(data.type === 'direct_message' ? { clientMsgId: data.clientMsgId } : {})
            });
            return;
        }

        if (data.type === 'hello_ack') {
            if (!connectionRegistry.beginAuthentication(ws.clientId)) {
                sendError(ws, 'AUTH_ALREADY_COMPLETED');
                ws.close(1008, 'Handshake already completed');
                return;
            }
            const context = normalizeClientContext(data);
            const deviceId = context.deviceId;
            const requestedLang = normalizeLang(context.locale || ws.prefLang, 'en');
            let dbUser = null;

            // Token authentication is mandatory. Guest/legacy fallback is intentionally unsupported.
            try {
                const session = await findValidSessionByToken(data.token);
                if (session) {
                    dbUser = {
                        id: session.user_id,
                        username: session.username,
                        nickname: session.display_name || session.username,
                        status: session.status,
                        sessionId: session.token_hash,
                        sessionExpiresAt: session.expires_at
                    };
                }
            } catch (e) {
                console.error('Token Auth Error:', e?.message || e);
            }

            if (!dbUser) {
                sendError(ws, 'AUTH_ERROR');
                ws.close(1008, 'Authentication required');
                return;
            }

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
            try {
                const legalStatus = await calculateLegalStatus(pool, dbUser.id);
                if (legalStatus.requiresReaccept) {
                    sendError(ws, 'LEGAL_REACCEPT_REQUIRED', null, {
                        retryable: false,
                        metadata: legalStatusPayload(legalStatus)
                    });
                    ws.close(1008, 'Legal reaccept required');
                    return;
                }
            } catch (error) {
                console.warn('WebSocket legal status unavailable:', { code: error?.code || 'LEGAL_STATUS_UNAVAILABLE' });
                sendError(ws, 'LEGAL_STATUS_UNAVAILABLE', null, { retryable: true });
                ws.close(1013, 'Legal status unavailable');
                return;
            }
            activeClients.set(ws.clientId, {
                ws,
                dbUserId: dbUser.id,
                deviceId: deviceId || 'unknown',
                isShadowBanned: isShadow,
                nickname: dbUser.nickname, // Display Name
                username: dbUser.username,  // V13: Store unique username
                sessionId: dbUser.sessionId,
                platform: context.platform,
                lang: requestedLang,
                release: context.release,
                capabilities: context.capabilities,
                connectedAt: new Date().toISOString()
            });
            connectionRegistry.authenticate(ws.clientId, {
                sessionId: dbUser.sessionId,
                userId: dbUser.id,
                deviceId,
                platform: context.platform,
                locale: requestedLang,
                release: context.release,
                capabilities: context.capabilities,
                expiresAt: new Date(dbUser.sessionExpiresAt).getTime()
            });

            const recovery = recoveryRegistry.attach({
                connectionId: ws.clientId,
                userId: dbUser.id,
                sessionId: dbUser.sessionId,
                deviceId: deviceId || 'unknown',
                recoveryToken: data.recoveryToken,
                previousServerEpoch: data.serverEpoch
            });
            const previousClient = recovery.previousConnectionId
                ? activeClients.get(recovery.previousConnectionId)
                : null;
            if (recovery.previousConnectionId) {
                rebindTransientState(recovery.previousConnectionId, ws.clientId, ws);
                const reboundPending = getPendingMatchForClient(ws.clientId);
                if (reboundPending && Date.now() >= reboundPending.pending.autoAcceptAt) {
                    const deadline = applyDeadline(reboundPending.pending);
                    deadline.changed.forEach((participant) => {
                        const live = activeClients.get(participant.clientId);
                        if (live?.ws?.readyState === WebSocket.OPEN) {
                            sendJson(live.ws, pendingEvent(reboundPending.pending, participant, 'match_decision_result', {
                                decision: 'accept',
                                decisionSource: 'auto',
                                result: 'accepted'
                            }));
                        }
                    });
                }
                if (reboundPending?.pending?.status === 'finalizing') {
                    await finalizePendingMatchIfReady(reboundPending.matchId, { trigger: 'recovery_resume' });
                }
            }
            if (previousClient?.ws && previousClient.ws !== ws) {
                previousClient.ws.superseded = true;
                sendJson(previousClient.ws, { type: 'error', errorCode: 'CONNECTION_SUPERSEDED', code: 'CONNECTION_SUPERSEDED', message: 'Connection superseded.', retryable: false });
                previousClient.ws.close(4001, 'superseded');
            }

            let partial = false;
            try {
                const opened = await presenceService.open({
                    connectionId: ws.clientId,
                    userId: dbUser.id,
                    sessionId: dbUser.sessionId,
                    deviceId: deviceId || 'unknown',
                    generation: recovery.lease.generation
                });
                if (opened.becameOnline) void broadcastPresence(dbUser.id, 'online');
            } catch (error) {
                partial = true;
                console.warn('presence lease open failed', { code: error?.code || 'PRESENCE_OPEN_FAILED' });
            }

            trackBehaviorEvent({
                eventName: 'user_connected',
                userId: dbUser.id,
                clientId: ws.clientId,
                deviceId: deviceId || 'unknown',
                platform: context.platform,
                metadata: {
                    lang: requestedLang,
                    is_anon: false,
                    app_version: context.release
                }
            });

            const capabilities = ['error-envelope-v1', 'session-revoke-v1', 'presence-v1', 'matchSearchLifecycleV1', 'matchScopesV1', 'pendingMatchV1'];
            if (realtimeConfig.recoveryEnabled) capabilities.push('recovery-v1');
            let countryState = null;
            try {
                countryState = await resolveCanonicalMatchScope({ pool, userId: dbUser.id, requestedScope: 'COUNTRY', locale: requestedLang });
            } catch {
                countryState = { ok: false, code: 'MATCH_COUNTRY_UNAVAILABLE' };
            }
            sendJson(ws, {
                type: 'welcome',
                nickname: dbUser.nickname,
                lang: requestedLang,
                capabilities,
                matchScopes: matchScopesCapability(countryState)
            });
            trackBehaviorEvent({
                eventName: 'match_scope_selector_seen',
                userId: dbUser.id,
                clientId: ws.clientId,
                deviceId: deviceId || 'unknown',
                platform: context.platform,
                metadata: {
                    event_version: 1,
                    country_available: Boolean(countryState?.ok),
                    default_scope: 'GLOBAL'
                }
            });
            let unread = { friends: [], system: 0, revision: 0 };
            try {
                unread = await loadUnreadSnapshot(dbUser.id);
            } catch (error) {
                partial = true;
                console.warn('recovery unread snapshot failed', { code: error?.code || 'UNREAD_SNAPSHOT_FAILED' });
            }
            sendJson(ws, buildRecoverySnapshot({
                recovery: {
                    ...recovery,
                    serverEpoch: recoveryRegistry.serverEpoch,
                    graceMs: realtimeConfig.recoveryGraceMs
                },
                active: recovery.result === 'resumed' ? buildActiveRecoveryState(ws.clientId) : { kind: 'idle' },
                unread,
                partial
            }));
            ws.recoveryReady = true;
            return;
        }

        const clientData = activeClients.get(ws.clientId);
        const registryEntry = connectionRegistry.get(ws.clientId);
        if (!clientData || !connectionRegistry.isAuthenticated(ws.clientId)
            || (Number.isFinite(registryEntry?.expiresAt) && registryEntry.expiresAt <= Date.now())) {
            sendError(ws, 'AUTH_ERROR');
            if (registryEntry?.expiresAt <= Date.now()) ws.close(1008, 'Session expired');
            return;
        }
        if (!ws.recoveryReady || !recoveryRegistry.isCurrentConnection(ws.clientId)) {
            sendError(ws, 'RECOVERY_PENDING');
            return;
        }

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
                await joinQueue(ws, {
                    trigger: 'manual',
                    searchId: data.searchId,
                    commandId: data.commandId,
                    scope: data.scope || 'GLOBAL'
                });
                break;

            case 'changeMatchScope':
                trackBehaviorEvent({
                    eventName: 'match_scope_change_started',
                    userId: clientData.dbUserId,
                    clientId: ws.clientId,
                    deviceId: clientData.deviceId || null,
                    platform: clientData.platform || null,
                    metadata: { search_id: data.fromSearchId, requested_scope: data.scope }
                });
                {
                    const changed = await joinQueue(ws, {
                        trigger: 'scope_change',
                        replaceFrom: data.fromSearchId,
                        searchId: data.searchId,
                        commandId: data.commandId,
                        scope: data.scope
                    });
                    trackBehaviorEvent({
                        eventName: 'match_scope_change_result',
                        userId: clientData.dbUserId,
                        clientId: ws.clientId,
                        deviceId: clientData.deviceId || null,
                        platform: clientData.platform || null,
                        metadata: {
                            search_id: data.searchId,
                            requested_scope: data.scope,
                            result: changed?.kind || 'rejected'
                        }
                    });
                    if (changed?.kind === 'accepted' && changed.previous?.fallbackStatus === 'eligible') {
                        trackBehaviorEvent({
                            eventName: 'match_country_fallback_action',
                            userId: clientData.dbUserId,
                            clientId: ws.clientId,
                            deviceId: clientData.deviceId || null,
                            platform: clientData.platform || null,
                            metadata: {
                                event_version: 1,
                                search_id: data.fromSearchId,
                                action: 'global',
                                effective_scope: 'COUNTRY',
                                country_code: changed.previous.country?.code || null
                            }
                        });
                    }
                }
                break;

            case 'countryFallbackAction':
                {
                    const fallbackEvent = searchLifecycle.recordFallbackAction({
                        connectionId: ws.clientId,
                        searchId: data.searchId,
                        action: data.action
                    });
                    if (!fallbackEvent) {
                        sendError(ws, 'STALE_SEARCH');
                        break;
                    }
                    sendJson(ws, fallbackEvent);
                    trackBehaviorEvent({
                        eventName: 'match_country_fallback_action',
                        userId: clientData.dbUserId,
                        clientId: ws.clientId,
                        deviceId: clientData.deviceId || null,
                        platform: clientData.platform || null,
                        metadata: { event_version: 1, search_id: data.searchId, action: data.action, effective_scope: 'COUNTRY' }
                    });
                }
                break;

            case 'matchDecision':
                {
                    const decision = toText(data.decision, '').trim().toLowerCase();
                    const matchId = toText(data.matchId, '').trim();
                    if (decision !== 'accept' && decision !== 'pass' && decision !== 'reject') {
                        const lang = resolveWsLang(ws);
                        sendError(ws, 'INVALID_INPUT', t(lang, 'errors.INVALID_INPUT', {}, 'Invalid request.'));
                        break;
                    }
                    await applyMatchDecision(ws, matchId, decision, {
                        commandId: data.commandId,
                        searchId: data.searchId
                    });
                }
                break;

            case 'matchOfferTelemetry':
                {
                    const context = getPendingMatchForClient(ws.clientId);
                    const participant = context?.pending?.users?.[context.participantIndex] || null;
                    if (!context || data.matchId !== context.matchId || data.searchId !== participant?.searchId) {
                        sendError(ws, 'STALE_MATCH');
                        break;
                    }
                    if (markOfferRendered(context.pending, ws.clientId)) {
                        trackBehaviorEvent({
                            eventName: 'match_offer_rendered',
                            userId: participant.dbUserId,
                            clientId: ws.clientId,
                            deviceId: clientData.deviceId || null,
                            platform: clientData.platform || null,
                            matchId: context.matchId,
                            metadata: {
                                event_version: 1,
                                search_id: participant.searchId,
                                effective_scope: participant.effectiveMatchScope
                            }
                        });
                    }
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
                    const clientMsgId = toClientMsgId(data.clientMsgId);
                    const dmSenderId = clientData.dbUserId;
                    const textValidation = validateDirectText(data.text);

                    if (!dmTargetUserId || !textValidation.ok) {
                        const errorCode = textValidation.code || 'MESSAGE_INVALID';
                        sendError(ws, errorCode, null, { clientMsgId: clientMsgId || undefined, retryable: false });
                        sendJson(ws, buildDirectMessageFailure({ clientMsgId, errorCode, retryable: false }));
                        break;
                    }
                    const dmText = textValidation.text;

                    if (!clientMsgId) {
                        sendError(ws, 'MESSAGE_INVALID', null, { retryable: false });
                        sendJson(ws, buildDirectMessageFailure({ errorCode: 'MESSAGE_INVALID', retryable: false }));
                        break;
                    }

                    try {
                        const fCheck = await pool.query(
                            'SELECT 1 FROM friendships WHERE ((user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)) AND status=\'accepted\'',
                            [dmSenderId, dmTargetUserId]
                        );
                        if (fCheck.rows.length === 0) {
                            sendError(ws, 'NOT_FRIEND', null, { clientMsgId, retryable: false });
                            sendJson(ws, buildDirectMessageFailure({ clientMsgId, errorCode: 'NOT_FRIEND', retryable: false }));
                            break;
                        }
                    } catch (e) {
                        console.error('direct_message friendship check error:', e.message);
                        sendError(ws, 'MESSAGE_RESULT_UNKNOWN', null, { clientMsgId, retryable: true });
                        sendJson(ws, buildDirectMessageFailure({ clientMsgId, errorCode: 'MESSAGE_RESULT_UNKNOWN', retryable: true }));
                        break;
                    }

                    let convId = null;
                    try {
                        convId = await resolveDirectConversation({
                            pool,
                            senderId: dmSenderId,
                            targetUserId: dmTargetUserId,
                            conversationId: uuidv4()
                        });
                    } catch (e) {
                        console.error('direct_message conversation error:', e.message);
                        sendError(ws, 'MESSAGE_PERSIST_RETRYABLE', null, { clientMsgId, retryable: true });
                        sendJson(ws, buildDirectMessageFailure({ clientMsgId, errorCode: 'MESSAGE_PERSIST_RETRYABLE', retryable: true }));
                        break;
                    }

                    if (!convId) {
                        sendError(ws, 'MESSAGE_PERSIST_RETRYABLE', null, { clientMsgId, retryable: true });
                        sendJson(ws, buildDirectMessageFailure({ clientMsgId, errorCode: 'MESSAGE_PERSIST_RETRYABLE', retryable: true }));
                        break;
                    }

                    let persistResult = null;
                    try {
                        persistResult = await persistDirectMessage({
                            pool,
                            conversationId: convId,
                            senderId: dmSenderId,
                            clientMsgId,
                            text: dmText,
                            messageId: uuidv4()
                        });
                    } catch (e) {
                        console.error('direct_message persist error:', e.message);
                        sendError(ws, 'MESSAGE_RESULT_UNKNOWN', null, { clientMsgId, retryable: true });
                        sendJson(ws, buildDirectMessageFailure({ clientMsgId, errorCode: 'MESSAGE_RESULT_UNKNOWN', retryable: true }));
                        break;
                    }

                    if (persistResult.kind === 'conflict') {
                        sendError(ws, 'MESSAGE_ID_CONFLICT', null, { clientMsgId, retryable: false });
                        sendJson(ws, buildDirectMessageFailure({ clientMsgId, errorCode: 'MESSAGE_ID_CONFLICT', retryable: false }));
                        break;
                    }

                    const canonicalAck = buildDirectMessageAck({ clientMsgId, result: persistResult });
                    sendJson(ws, canonicalAck);
                    if (persistResult.kind === 'replayed') break;

                    convId = persistResult.row.conversation_id;
                    const dmDeliveryId = uuidv4();
                    const dmEvent = {
                        type: 'direct_message',
                        protocolVersion: 1,
                        fromUsername: clientData.username,
                        fromNickname: clientData.nickname,
                        fromUserId: dmSenderId,
                        targetUserId: dmTargetUserId,
                        msgType: 'direct',
                        text: dmText,
                        serverMessageId: persistResult.row.id,
                        conversationId: convId,
                        createdAt: persistResult.row.created_at,
                        deliveryId: dmDeliveryId,
                        clientMsgId
                    };
                    let dmTargetClient = null;
                    for (const [clientId, cData] of activeClients) {
                        if (cData.dbUserId === dmTargetUserId) {
                            dmTargetClient = dmTargetClient || cData;
                            sendJson(cData.ws, dmEvent);
                        } else if (cData.dbUserId === dmSenderId && clientId !== ws.clientId) {
                            sendJson(cData.ws, {
                                ...dmEvent,
                                fromUsername: clientData.username,
                                fromNickname: clientData.nickname
                            });
                        }
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

                }
                break;

            case 'typing':
            case 'stop_typing':
                if (data.targetUserId) {
                    const typingFriendship = await pool.query(
                        'SELECT 1 FROM friendships WHERE ((user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)) AND status=\'accepted\'',
                        [clientData.dbUserId, data.targetUserId]
                    ).catch(() => ({ rows: [] }));
                    if (typingFriendship.rows.length > 0) {
                        for (const [, cData] of activeClients) {
                            if (cData.dbUserId === data.targetUserId) {
                                sendJson(cData.ws, {
                                    type: data.type,
                                    fromUserId: clientData.dbUserId
                                });
                            }
                        }
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
                {
                    const currentSearch = searchLifecycle.getByConnection(ws.clientId);
                    const cancelResult = searchLifecycle.cancel({
                        userId: clientData.dbUserId,
                        connectionId: ws.clientId,
                        searchId: data.searchId || currentSearch?.searchId,
                        commandId: data.commandId,
                        reason: data.reason || 'user_cancelled'
                    });
                    sendJson(ws, cancelResult.event);
                    if (cancelResult.kind === 'cancelled') {
                        removeFromQueue(ws.clientId);
                        cancelPendingMatchForClient(ws.clientId, {
                            actorReason: null,
                            peerReason: 'peer_cancelled',
                            requeueActor: false,
                            requeuePeers: true
                        });
                        trackBehaviorEvent({
                            eventName: 'match_search_cancelled',
                            userId: clientData.dbUserId,
                            clientId: ws.clientId,
                            deviceId: clientData.deviceId || null,
                            platform: clientData.platform || null,
                            metadata: { search_id: cancelResult.record.searchId, queue_attempt: cancelResult.record.queueAttempt }
                        });
                    }
                }
                break;

            case 'next':
                cancelPendingMatchForClient(ws.clientId, {
                    actorReason: null,
                    peerReason: 'peer_rejected',
                    requeueActor: false,
                    requeuePeers: true
                });
                leaveRoom(ws.clientId, 'next');
                await joinQueue(ws, { trigger: 'next' }); // Join with existing nickname
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
                trackBehaviorEvent({
                    eventName: 'chat_leave_action',
                    userId: clientData.dbUserId,
                    clientId: ws.clientId,
                    deviceId: clientData.deviceId || null,
                    platform: clientData.platform || null
                });
                break;

            case 'image_send':
                if (!data.roomId || !data.imageData) return;
                const imageValidation = validateImageDataUrl(data.imageData);
                if (!imageValidation.ok) return sendError(ws, imageValidation.code || 'INVALID_IMAGE');
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
                        `INSERT INTO ephemeral_media
                          (sender_id,receiver_id,conversation_id,media_data,content_type,byte_size,width,height,content_fingerprint,status,expires_at,policy_version)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'available',NOW() + INTERVAL '7 days','talkx-media-policy-wave11-v1') RETURNING id`,
                        [iSender.dbUserId, iReceiver.dbUserId, iRoom.conversationId || null, imageValidation.dataUrl,
                            imageValidation.contentType, imageValidation.byteSize, imageValidation.width,
                            imageValidation.height, imageValidation.fingerprint]
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
                    const consumed = await consumeImage({ pool, mediaId: data.mediaId, receiverId: clientDataFetch.dbUserId });
                    if (!consumed.ok) {
                        trackBehaviorEvent({
                            eventName: 'media_fetch_result', userId: clientDataFetch.dbUserId, clientId: ws.clientId,
                            deviceId: clientDataFetch.deviceId || null, platform: clientDataFetch.platform || null,
                            metadata: { result: consumed.code, status: consumed.status || 'unavailable', revision: consumed.revision || null }
                        });
                        return sendJson(ws, {
                            type: 'image_error',
                            code: consumed.code,
                            mediaId: data.mediaId,
                            mediaStatus: consumed.status || (consumed.code === 'MEDIA_ALREADY_CONSUMED' ? 'consumed' : 'unavailable'),
                            revision: consumed.revision || null,
                            retryable: consumed.code === 'MEDIA_UNAVAILABLE',
                            message: t(resolveWsLang(ws), 'ws.MEDIA_EXPIRED', {}, 'Photo is no longer available.')
                        });
                    }
                    sendJson(ws, {
                        type: 'image_data',
                        mediaId: data.mediaId,
                        imageData: consumed.media_data,
                        contentType: consumed.content_type,
                        mediaStatus: 'consumed',
                        revision: consumed.revision
                    });
                    trackBehaviorEvent({
                        eventName: 'media_fetch_result', userId: clientDataFetch.dbUserId, clientId: ws.clientId,
                        deviceId: clientDataFetch.deviceId || null, platform: clientDataFetch.platform || null,
                        metadata: { result: 'consumed', status: 'consumed', revision: consumed.revision }
                    });
                } catch (e) {
                    console.error('fetch_image error', e);
                    sendJson(ws, { type: 'image_error', code: 'MEDIA_FETCH_FAILED', mediaId: data.mediaId, mediaStatus: 'unavailable' });
                }
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
                        trackBehaviorEvent({
                            eventName: 'media_validation_rejected', userId: distSenderId, clientId: ws.clientId,
                            deviceId: clientData.deviceId || null, platform: clientData.platform || null,
                            metadata: { reason_code: v.code || 'INVALID_IMAGE' }
                        });
                        sendError(ws, v.code || 'INVALID_IMAGE', null, { clientMsgId });
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

                        const dConvId = await findOrCreatePersistentConversation(distSenderId, distTargetUserId);
                        if (!dConvId) {
                            sendError(ws, 'CONVERSATION_CREATE_FAILED', null, { clientMsgId });
                            sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                            break;
                        }

                        const persisted = await persistDirectImage({
                            pool,
                            senderId: distSenderId,
                            receiverId: distTargetUserId,
                            conversationId: dConvId,
                            clientMsgId,
                            imageData: v.dataUrl,
                            validated: v
                        });
                        const dMediaId = persisted.mediaId;
                        const serverMessageId = persisted.serverMessageId;
                        trackBehaviorEvent({
                            eventName: 'media_upload_result', userId: distSenderId, clientId: ws.clientId,
                            deviceId: clientData.deviceId || null, platform: clientData.platform || null,
                            conversationId: dConvId,
                            metadata: { result: persisted.duplicate ? 'duplicate' : 'available', status: persisted.mediaStatus, revision: persisted.revision }
                        });
                        if (persisted.duplicate) {
                            sendJson(ws, {
                                type: 'direct_message_ack',
                                clientMsgId,
                                status: 'duplicate',
                                serverMessageId,
                                conversationId: persisted.conversationId,
                                mediaId: dMediaId,
                                mediaStatus: persisted.mediaStatus,
                                revision: persisted.revision,
                                expiresAt: persisted.expiresAt
                            });
                            break;
                        }

                        const dTargetClients = [];
                        for (const [, cData] of activeClients) {
                            if (cData.dbUserId === distTargetUserId) {
                                dTargetClients.push(cData);
                            }
                        }

                        const dTargetLang = await resolveUserLang(distTargetUserId, normalizeLang(dTargetClients[0]?.lang, 'en'));
                        const localizedPhotoText = t(dTargetLang, 'ws.PHOTO_SENT', {}, 'Photo sent');
                        const imageDeliveryId = uuidv4();
                        for (const dTargetClient of dTargetClients) {
                            sendJson(dTargetClient.ws, {
                                type: 'direct_message',
                                fromUserId: distSenderId,
                                fromUsername: clientData.username,
                                fromNickname: clientData.nickname,
                                msgType: 'image',
                                mediaId: dMediaId,
                                mediaStatus: 'available',
                                revision: persisted.revision,
                                expiresAt: persisted.expiresAt,
                                serverMessageId,
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
                            mediaStatus: 'available',
                            revision: persisted.revision,
                            expiresAt: persisted.expiresAt,
                            targetUserId: distTargetUserId,
                            clientMsgId
                        });

                        sendJson(ws, {
                            type: 'direct_message_ack',
                            clientMsgId,
                            status: 'sent',
                            serverMessageId,
                            conversationId: dConvId,
                            mediaId: dMediaId,
                            mediaStatus: persisted.mediaStatus,
                            revision: persisted.revision,
                            expiresAt: persisted.expiresAt
                        });
                    } catch (e) {
                        console.error('direct_image_send error', e);
                        sendError(ws, e?.code === 'IDEMPOTENCY_CONFLICT' ? 'IDEMPOTENCY_CONFLICT' : 'PHOTO_SEND_FAILED', null, { clientMsgId });
                        sendJson(ws, { type: 'direct_message_ack', clientMsgId, status: 'failed' });
                    }
                }
                break;


            case 'report':
                {
                    const reason = String(data.reason || '').trim();
                    const commandId = toClientMsgId(data.commandId) || uuidv4();
                    const reasonCategory = String(data.reasonCategory || 'other').trim().toLowerCase();
                    const allowedReasons = new Set(['spam', 'harassment', 'hate', 'sexual', 'threat', 'scam', 'other']);
                    if (!reason) {
                        sendError(ws, 'INVALID_INPUT');
                        break;
                    }
                    if (!allowedReasons.has(reasonCategory)) {
                        sendError(ws, 'INVALID_REPORT_REQUEST');
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
                        reason,
                        commandId,
                        reasonCategory,
                        messageId: data.messageId || null,
                        mediaId: data.mediaId || null
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
                        commandId,
                        evidenceAvailability: 'metadata_only',
                        duplicate: !!reportResult.duplicate,
                        message: t(resolveWsLang(ws), 'ws.REPORT_OK', {}, 'Your report has been sent.')
                    });
                    trackBehaviorEvent({
                        eventName: 'report_submitted', userId: clientData.dbUserId, clientId: ws.clientId,
                        deviceId: clientData.deviceId || null, platform: clientData.platform || null,
                        conversationId: conversationIdHint,
                        metadata: { result: reportResult.duplicate ? 'duplicate' : 'recorded', reason_category: reasonCategory, evidence_availability: 'metadata_only' }
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

    ws.on('close', (code, reasonBuffer) => {
        connectionRegistry.close(ws.clientId);
        const clientData = activeClients.get(ws.clientId) || null;
        const closeReason = String(reasonBuffer || '').toLowerCase();
        trackBehaviorEvent({
            eventName: 'user_disconnected',
            userId: clientData?.dbUserId || null,
            clientId: ws.clientId,
            deviceId: clientData?.deviceId || null,
            platform: clientData?.platform || null
        });
        if (activeClients.get(ws.clientId)?.ws === ws) activeClients.delete(ws.clientId);

        if (!ws.superseded) {
            const cleanupTransient = () => {
                cancelPendingMatchForClient(ws.clientId, {
                    actorReason: null,
                    peerReason: 'peer_disconnected',
                    requeueActor: false,
                    requeuePeers: true
                });
                removeFromQueue(ws.clientId);
                leaveRoom(ws.clientId, 'disconnect');
                searchLifecycle.terminate(ws.clientId, 'disconnect');
                presenceService.closeFinal(ws.clientId)
                    .then((result) => {
                        if (result?.becameOffline) void broadcastPresence(result.userId, 'offline', result.lastSeenAt);
                    })
                    .catch((error) => console.warn('presence final close failed', { code: error?.code || 'PRESENCE_CLOSE_FAILED' }));
            };
            const recoverableClose = code !== 1008
                && closeReason !== 'server_shutdown'
                && closeReason !== 'superseded';
            const deferred = realtimeConfig.recoveryEnabled && recoverableClose
                && recoveryRegistry.detach(ws.clientId, cleanupTransient);
            if (deferred) {
                presenceService.detach(ws.clientId).catch((error) => {
                    console.warn('presence detach failed', { code: error?.code || 'PRESENCE_DETACH_FAILED' });
                });
            } else {
                const lease = recoveryRegistry.getByConnection(ws.clientId);
                if (lease) recoveryRegistry.expire(lease.token, 'state_missing');
                cleanupTransient();
            }
        }
        broadcastOnlineCount();
    });
});

const handleReport = async ({
    reporterClientId,
    reporterDbUserId,
    roomId,
    targetUserId,
    conversationIdHint,
    reason,
    commandId,
    reasonCategory,
    messageId,
    mediaId
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

        const fallback = await logReport(reporterId, reportedId, fallbackConversationId, cleanReason, {
            commandId, reasonCategory, messageId, mediaId
        });
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
        const subject = await resolveReportSubject(reportedId, conversationId, messageId, mediaId);
        await pool.query(
            `INSERT INTO reports
              (reporter_user_id,reported_user_id,conversation_id,reason,meta,command_id,reason_category,subject_message_id,subject_media_id,evidence_availability,moderation_status,protocol_version)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'metadata_only','received','wave11-v1')
             ON CONFLICT (reporter_user_id,command_id) WHERE command_id IS NOT NULL DO NOTHING`,
            [reporterId, reportedId, conversationId, cleanReason,
                JSON.stringify({ weight, evidence_policy: 'metadata_only', content_retained: false, media_status: subject.mediaStatus }),
                commandId || null, reasonCategory || 'other', subject.messageId, subject.mediaId]
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
            await auditAutomaticBan({ reportedId, banHours, source: 'weighted_report_threshold', score: score24h, reporterCount: reporters24h });

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
    if (!presenceCleanupRunning) {
        presenceCleanupRunning = true;
        presenceService.cleanupExpired()
            .then((users) => Promise.all(users.map((user) => broadcastPresence(user.userId, 'offline', user.lastSeenAt))))
            .catch((error) => console.warn('presence expiry cleanup failed', { code: error?.code || 'PRESENCE_CLEANUP_FAILED' }))
            .finally(() => { presenceCleanupRunning = false; });
    }
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

// Serve Frontend Static Files (Production) when the web build is present.
const frontendDistPath = path.join(__dirname, '../chatapp-frontend/dist');
const frontendIndexPath = path.join(frontendDistPath, 'index.html');
if (fs.existsSync(frontendIndexPath)) {
    app.use(express.static(frontendDistPath));
    app.get('*', (req, res) => {
        res.sendFile(frontendIndexPath);
    });
} else {
    app.get('/', (req, res) => {
        res.status(200).send('TalkX backend is running. Frontend build is not bundled on this service.');
    });
}

const startServer = async () => {
    try {
        assertMatchScopeTopology(realtimeConfig);
        await ensureTables();
        startNotificationScheduler();
        server.listen(port, () => {
            console.log(`Backend running on ${port}`);
        });
    } catch (error) {
        console.error('Fatal startup error: database initialization failed.', {
            code: error?.code || 'DB_INITIALIZATION_FAILED'
        });
        process.exit(1);
    }
};

let shutdownPromise = null;
const shutdown = (signal) => {
    if (shutdownPromise) return shutdownPromise;
    healthState.shuttingDown = true;
    clearInterval(interval);
    if (notificationSchedulerState.timer) clearTimeout(notificationSchedulerState.timer);
    for (const client of wss.clients) {
        try { client.close(1001, 'server_shutdown'); } catch { /* best effort */ }
    }

    shutdownPromise = new Promise((resolve) => {
        const forceTimer = setTimeout(resolve, 8000);
        server.close(() => {
            clearTimeout(forceTimer);
            resolve();
        });
    })
        .then(() => closeDatabase())
        .then(() => {
            console.log('Graceful shutdown complete.', { signal });
            process.exit(0);
        })
        .catch((error) => {
            console.error('Graceful shutdown failed.', { code: error?.code || 'SHUTDOWN_FAILED' });
            process.exit(1);
        });
    return shutdownPromise;
};

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));

startServer();

