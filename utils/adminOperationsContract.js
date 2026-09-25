const crypto = require('crypto');

const SUPPORT_WORKFLOW_STATES = Object.freeze(['new', 'investigating', 'resolved', 'duplicate', 'insufficient_info', 'archived']);
const SUPPORT_PRIORITIES = Object.freeze(['low', 'normal', 'high', 'critical']);
const WORKFLOW_TRANSITIONS = Object.freeze({
    new: new Set(['investigating', 'resolved', 'duplicate', 'insufficient_info', 'archived']),
    investigating: new Set(['new', 'resolved', 'duplicate', 'insufficient_info', 'archived']),
    resolved: new Set(['investigating', 'archived']),
    duplicate: new Set(['investigating', 'archived']),
    insufficient_info: new Set(['investigating', 'archived']),
    archived: new Set(['new', 'investigating', 'resolved', 'duplicate', 'insufficient_info'])
});

const normalizeToken = (value, max = 120) => String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .slice(0, max);

const maskIp = (value) => {
    const raw = String(value || '').trim();
    if (!raw) return null;
    const ipv4 = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4) return `${ipv4[1]}.${ipv4[2]}.*.*`;
    const groups = raw.split(':').filter(Boolean);
    return groups.length ? `${groups.slice(0, 2).join(':')}:…` : '***';
};

const maskIdentifier = (value) => {
    const raw = String(value || '').trim();
    if (!raw) return null;
    if (raw.length <= 8) return `${raw.slice(0, 2)}***`;
    return `${raw.slice(0, 4)}…${raw.slice(-4)}`;
};

const maskEmail = (value) => {
    const raw = String(value || '').trim();
    const at = raw.indexOf('@');
    if (at <= 0) return raw ? '***' : null;
    return `${raw.slice(0, 1)}***${raw.slice(Math.max(1, at - 1), at)}@${raw.slice(at + 1)}`;
};

const locationState = ({ source, resolvedAt, city, country }, { now = Date.now(), staleAfterMs = 30 * 24 * 60 * 60 * 1000 } = {}) => {
    const normalizedSource = normalizeToken(source, 40);
    if (!normalizedSource || normalizedSource === 'none') return 'not_available';
    if (normalizedSource === 'unresolved') return 'unresolved';
    if (normalizedSource === 'provider_error') return 'provider_error';
    const resolvedMs = resolvedAt ? new Date(resolvedAt).getTime() : NaN;
    if (Number.isFinite(resolvedMs) && now - resolvedMs > staleAfterMs) return 'stale';
    if (city || country || normalizedSource === 'local' || normalizedSource === 'private') return 'resolved';
    return 'pending';
};

const buildSupportFingerprint = ({ subject, lastErrorCode, platform, appVersion } = {}) => {
    const parts = [subject, lastErrorCode, platform, appVersion].map((value) => normalizeToken(value));
    if (!parts[0] && !parts[1]) return null;
    return crypto.createHash('sha256').update(`wave15-v1|${parts.join('|')}`).digest('hex');
};

const validateWorkflowTransition = ({ current, next }) => {
    const from = normalizeToken(current, 40) || 'new';
    const to = normalizeToken(next, 40);
    if (!SUPPORT_WORKFLOW_STATES.includes(to)) return { ok: false, code: 'INVALID_WORKFLOW_STATUS' };
    if (from === to) return { ok: true, noOp: true, from, to };
    if (!WORKFLOW_TRANSITIONS[from]?.has(to)) return { ok: false, code: 'INVALID_WORKFLOW_TRANSITION', from, to };
    return { ok: true, noOp: false, from, to };
};

const isSafeSupportMediaType = (value) => new Set([
    'image/jpeg', 'image/png', 'image/webp', 'video/mp4', 'video/webm'
]).has(String(value || '').trim().toLowerCase());

module.exports = {
    SUPPORT_PRIORITIES,
    SUPPORT_WORKFLOW_STATES,
    buildSupportFingerprint,
    isSafeSupportMediaType,
    locationState,
    maskEmail,
    maskIdentifier,
    maskIp,
    validateWorkflowTransition
};
