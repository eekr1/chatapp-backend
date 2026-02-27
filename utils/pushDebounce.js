const toPositiveInt = (value, fallback) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
    return Math.round(parsed);
};

const DEBOUNCE_WINDOW_MS = toPositiveInt(process.env.PUSH_DM_DEBOUNCE_MS, 15000);
const DEBOUNCE_MAX_KEYS = toPositiveInt(process.env.PUSH_DM_DEBOUNCE_MAX_KEYS, 50000);

const recentPushMap = new Map();

const makeKey = ({ targetUserId, conversationId, eventType }) => {
    const target = String(targetUserId || 'unknown-target').trim() || 'unknown-target';
    const conversation = String(conversationId || 'no-conversation').trim() || 'no-conversation';
    const event = String(eventType || 'unknown-event').trim() || 'unknown-event';
    return `${target}:${conversation}:${event}`;
};

const pruneExpired = (nowMs) => {
    for (const [key, ts] of recentPushMap.entries()) {
        if (nowMs - ts > DEBOUNCE_WINDOW_MS) recentPushMap.delete(key);
    }
};

const pruneOverflow = () => {
    if (recentPushMap.size <= DEBOUNCE_MAX_KEYS) return;
    const overflow = recentPushMap.size - DEBOUNCE_MAX_KEYS;
    const oldest = Array.from(recentPushMap.entries())
        .sort((a, b) => a[1] - b[1])
        .slice(0, overflow);
    oldest.forEach(([key]) => recentPushMap.delete(key));
};

const shouldDebouncePush = ({ targetUserId, conversationId, eventType }) => {
    const nowMs = Date.now();
    pruneExpired(nowMs);

    const key = makeKey({ targetUserId, conversationId, eventType });
    const previousTs = recentPushMap.get(key);
    if (previousTs) {
        const elapsedMs = nowMs - previousTs;
        if (elapsedMs < DEBOUNCE_WINDOW_MS) {
            return {
                debounced: true,
                key,
                waitMs: Math.max(0, DEBOUNCE_WINDOW_MS - elapsedMs),
                windowMs: DEBOUNCE_WINDOW_MS
            };
        }
    }

    recentPushMap.set(key, nowMs);
    pruneOverflow();
    return {
        debounced: false,
        key,
        waitMs: 0,
        windowMs: DEBOUNCE_WINDOW_MS
    };
};

const getPushDebounceConfig = () => ({
    windowMs: DEBOUNCE_WINDOW_MS,
    maxKeys: DEBOUNCE_MAX_KEYS
});

module.exports = {
    shouldDebouncePush,
    getPushDebounceConfig
};
