const NOTICE_LOCALES = Object.freeze(['tr', 'en']);
const NOTICE_TARGETS = Object.freeze(['all', 'online', 'mobile']);
const NOTICE_FALLBACK_LOCALE = 'en';
const NOTICE_TITLE_MAX = 120;
const NOTICE_BODY_MAX = 400;

const normalizeNoticeTarget = (value, fallback = null) => {
    const normalized = String(value || '').trim().toLowerCase();
    if (NOTICE_TARGETS.includes(normalized)) return normalized;
    return fallback;
};

const normalizeNoticeContentByLocale = (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const content = {};
    for (const locale of NOTICE_LOCALES) {
        const variant = value[locale];
        const title = String(variant?.title || '').trim();
        const body = String(variant?.body || '').trim();
        if (!title || !body || title.length > NOTICE_TITLE_MAX || body.length > NOTICE_BODY_MAX) {
            return null;
        }
        content[locale] = { title, body };
    }
    return content;
};

const emptyLocaleCounts = () => ({ tr: 0, en: 0, fallback: 0 });

const buildAudienceSummary = ({ target, online = [], push = [] } = {}) => {
    const normalizedTarget = normalizeNoticeTarget(target, 'all');
    const includeOnline = normalizedTarget === 'all' || normalizedTarget === 'online';
    const includePush = normalizedTarget === 'all' || normalizedTarget === 'mobile';
    const recipientIds = new Set();
    const onlineUserIds = new Set();
    const pushUserIds = new Set();
    const localeCounts = emptyLocaleCounts();

    if (includeOnline) {
        for (const item of online) {
            if (item?.userId) {
                recipientIds.add(String(item.userId));
                onlineUserIds.add(String(item.userId));
            }
            const locale = NOTICE_LOCALES.includes(item?.locale) ? item.locale : 'en';
            localeCounts[locale] += 1;
            if (item?.fallback) localeCounts.fallback += 1;
        }
    }

    if (includePush) {
        for (const item of push) {
            if (item?.userId) {
                recipientIds.add(String(item.userId));
                pushUserIds.add(String(item.userId));
            }
            const locale = NOTICE_LOCALES.includes(item?.locale) ? item.locale : 'en';
            localeCounts[locale] += 1;
            if (item?.fallback) localeCounts.fallback += 1;
        }
    }

    return {
        target: normalizedTarget,
        recipientCount: recipientIds.size,
        wsConnections: includeOnline ? online.length : 0,
        wsUsers: includeOnline ? onlineUserIds.size : 0,
        pushDevices: includePush ? push.length : 0,
        pushUsers: includePush ? pushUserIds.size : 0,
        localeDeliveries: localeCounts
    };
};

module.exports = {
    NOTICE_BODY_MAX,
    NOTICE_FALLBACK_LOCALE,
    NOTICE_LOCALES,
    NOTICE_TARGETS,
    NOTICE_TITLE_MAX,
    buildAudienceSummary,
    normalizeNoticeContentByLocale,
    normalizeNoticeTarget
};
