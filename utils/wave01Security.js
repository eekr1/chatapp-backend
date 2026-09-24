const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const WS_MAX_PAYLOAD_BYTES = 3 * 1024 * 1024;
const CHAT_MESSAGE_MAX_LENGTH = 2000;
const REPORT_REASON_MAX_LENGTH = 800;

const isPlainObject = (value) => Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;

const isUuid = (value) => typeof value === 'string' && UUID_RE.test(value);
const isString = (value, { min = 0, max = Number.MAX_SAFE_INTEGER, trim = false } = {}) => {
    if (typeof value !== 'string') return false;
    const candidate = trim ? value.trim() : value;
    return candidate.length >= min && candidate.length <= max;
};

const field = (check, required = true) => ({ check, required });
const optional = (check) => field(check, false);
const noFields = {};

const EVENT_SCHEMAS = {
    hello_ack: {
        deviceId: field((value) => isString(value, { min: 1, max: 200, trim: true })),
        token: field((value) => isString(value, { min: 16, max: 512, trim: true })),
        platform: field((value) => value === 'web' || value === 'android'),
        lang: optional((value) => value === 'tr' || value === 'en'),
        appVersion: optional((value) => isString(value, { max: 60, trim: true })),
        version: optional((value) => isString(value, { max: 60, trim: true })),
        capabilities: optional((value) => Array.isArray(value)
            && value.length <= 30
            && value.every((item) => isString(item, { min: 1, max: 60, trim: true }))),
        recoveryToken: optional((value) => isString(value, { min: 32, max: 128, trim: true })),
        serverEpoch: optional((value) => isString(value, { min: 1, max: 80, trim: true }))
    },
    setNickname: { nickname: field((value) => isString(value, { min: 3, max: 40, trim: true })) },
    joinQueue: {
        protocolVersion: optional((value) => value === 1),
        searchId: optional(isUuid),
        commandId: optional(isUuid),
        scope: optional((value) => value === 'GLOBAL' || value === 'COUNTRY')
    },
    changeMatchScope: {
        protocolVersion: field((value) => value === 1),
        fromSearchId: field(isUuid),
        searchId: field(isUuid),
        commandId: field(isUuid),
        scope: field((value) => value === 'GLOBAL' || value === 'COUNTRY')
    },
    countryFallbackAction: {
        protocolVersion: field((value) => value === 1),
        searchId: field(isUuid),
        commandId: field(isUuid),
        action: field((value) => value === 'continue' || value === 'dismiss')
    },
    matchDecision: {
        matchId: field(isUuid),
        decision: field((value) => value === 'accept' || value === 'pass' || value === 'reject'),
        protocolVersion: optional((value) => value === 1),
        searchId: optional(isUuid),
        commandId: optional(isUuid)
    },
    matchOfferTelemetry: {
        matchId: field(isUuid),
        searchId: field(isUuid),
        eventName: field((value) => value === 'match_offer_rendered')
    },
    message: { roomId: field(isUuid), text: field((value) => isString(value, { min: 1, max: CHAT_MESSAGE_MAX_LENGTH, trim: true })) },
    direct_message: {
        targetUserId: field(isUuid),
        text: field((value) => isString(value, { min: 1, max: CHAT_MESSAGE_MAX_LENGTH, trim: true })),
        clientMsgId: field((value) => isString(value, { min: 1, max: 120, trim: true }))
    },
    typing: { targetUserId: optional(isUuid) },
    stop_typing: { targetUserId: optional(isUuid) },
    leaveQueue: {
        protocolVersion: optional((value) => value === 1),
        searchId: optional(isUuid),
        commandId: optional(isUuid),
        reason: optional((value) => value === 'user_cancelled' || value === 'screen_closed')
    },
    next: noFields,
    leave: noFields,
    image_send: { roomId: field(isUuid), imageData: field((value) => isString(value, { min: 1, max: WS_MAX_PAYLOAD_BYTES })) },
    fetch_image: { mediaId: field(isUuid) },
    direct_image_send: {
        targetUserId: field(isUuid),
        imageData: field((value) => isString(value, { min: 1, max: WS_MAX_PAYLOAD_BYTES })),
        clientMsgId: field((value) => isString(value, { min: 1, max: 120, trim: true }))
    },
    report: {
        reason: field((value) => isString(value, { min: 1, max: REPORT_REASON_MAX_LENGTH, trim: true })),
        roomId: optional(isUuid),
        targetUserId: optional(isUuid),
        conversationId: optional(isUuid)
    },
    joinDirect: { targetUsername: field((value) => isString(value, { min: 3, max: 40, trim: true })) }
};

const validateWsEvent = (payload) => {
    if (!isPlainObject(payload)) return { ok: false, code: 'INVALID_PAYLOAD' };
    if (!isString(payload.type, { min: 1, max: 60, trim: true })) return { ok: false, code: 'INVALID_EVENT_TYPE' };
    const schema = EVENT_SCHEMAS[payload.type];
    if (!schema) return { ok: false, code: 'UNKNOWN_EVENT' };
    const allowedKeys = new Set(['type', ...Object.keys(schema)]);
    if (Object.keys(payload).some((key) => !allowedKeys.has(key))) return { ok: false, code: 'UNEXPECTED_FIELD' };
    for (const [name, rule] of Object.entries(schema)) {
        const present = Object.prototype.hasOwnProperty.call(payload, name);
        if (!present || payload[name] === undefined || payload[name] === null) {
            if (rule.required) return { ok: false, code: 'INVALID_INPUT' };
            continue;
        }
        if (!rule.check(payload[name])) return { ok: false, code: 'INVALID_INPUT' };
    }
    if (payload.type === 'report' && !payload.roomId && !payload.targetUserId) return { ok: false, code: 'INVALID_INPUT' };
    if (payload.type === 'joinQueue' || payload.type === 'leaveQueue') {
        const lifecycleFields = ['protocolVersion', 'searchId', 'commandId'];
        const count = lifecycleFields.filter((name) => Object.prototype.hasOwnProperty.call(payload, name)).length;
        if (count !== 0 && count !== lifecycleFields.length) return { ok: false, code: 'INVALID_INPUT' };
    }
    if (payload.type === 'matchDecision') {
        const identityFields = ['protocolVersion', 'searchId', 'commandId'];
        const count = identityFields.filter((name) => Object.prototype.hasOwnProperty.call(payload, name)).length;
        if (count !== 0 && count !== identityFields.length) return { ok: false, code: 'INVALID_INPUT' };
    }
    return { ok: true, event: payload };
};

const normalizeOrigin = (origin) => {
    if (typeof origin !== 'string' || !origin.trim()) return null;
    try {
        const url = new URL(origin.trim());
        return url.origin === 'null' ? `${url.protocol}//${url.host}` : url.origin;
    } catch {
        return null;
    }
};
const isAllowedWebSocketOrigin = (origin, allowedOrigins) => {
    const normalized = normalizeOrigin(origin);
    return Boolean(normalized && allowedOrigins.has(normalized));
};

module.exports = {
    CHAT_MESSAGE_MAX_LENGTH,
    EVENT_SCHEMAS,
    REPORT_REASON_MAX_LENGTH,
    WS_MAX_PAYLOAD_BYTES,
    isAllowedWebSocketOrigin,
    validateWsEvent
};
