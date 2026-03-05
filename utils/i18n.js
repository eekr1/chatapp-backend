const messagesTr = require('../i18n/messages.tr');
const messagesEn = require('../i18n/messages.en');

const SUPPORTED = new Set(['tr', 'en']);
const DEFAULT_LANG = 'en';

const dictionaries = {
    tr: messagesTr,
    en: messagesEn
};

const normalizeLang = (value, fallback = DEFAULT_LANG) => {
    const raw = String(value || '').trim().toLowerCase();
    if (!raw) return fallback;
    if (SUPPORTED.has(raw)) return raw;
    if (raw.startsWith('tr')) return 'tr';
    if (raw.startsWith('en')) return 'en';
    return fallback;
};

const resolveLangFromHeaders = (headers = {}) => {
    const explicit = normalizeLang(headers['x-talkx-lang'], null);
    if (explicit) return explicit;
    return normalizeLang(headers['accept-language'], DEFAULT_LANG);
};

const resolveRequestLang = (req) => {
    if (!req || typeof req !== 'object') return DEFAULT_LANG;
    return resolveLangFromHeaders(req.headers || {});
};

const getNestedValue = (obj, path) => String(path || '')
    .split('.')
    .reduce((acc, key) => (acc && typeof acc === 'object' ? acc[key] : undefined), obj);

const interpolate = (template, params = {}) => {
    if (typeof template !== 'string') return template;
    return template.replace(/\{([^}]+)\}/g, (_, key) => {
        if (params[key] === undefined || params[key] === null) return '';
        return String(params[key]);
    });
};

const t = (lang, key, params = {}, fallback = null) => {
    const normalized = normalizeLang(lang, DEFAULT_LANG);
    const dict = dictionaries[normalized] || dictionaries.en;
    const fallbackDict = dictionaries.en;
    const resolved = getNestedValue(dict, key) ?? getNestedValue(fallbackDict, key) ?? fallback ?? key;
    return interpolate(resolved, params);
};

const sendApiError = (req, res, status, code, params = {}, fallbackKey = 'errors.SERVER_ERROR') => {
    const lang = resolveRequestLang(req);
    const key = `errors.${code || 'SERVER_ERROR'}`;
    const error = t(lang, key, params, t(lang, fallbackKey, {}, 'Server error.'));
    return res.status(status).json({ error, code: code || 'SERVER_ERROR' });
};

module.exports = {
    DEFAULT_LANG,
    normalizeLang,
    resolveLangFromHeaders,
    resolveRequestLang,
    t,
    sendApiError
};
