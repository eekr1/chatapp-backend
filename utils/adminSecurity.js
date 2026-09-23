const crypto = require('crypto');
const { BoundedRateLimiter, hashKey, resolvePeerAddress } = require('./abuseProtection');
const { buildErrorEnvelope } = require('./contracts');

const ADMIN_CAPABILITIES = Object.freeze({
    READ: 'read',
    SENSITIVE_READ: 'sensitive-read',
    ACTION: 'moderation/action',
    CONTENT: 'content/publish',
    DELETION: 'account/deletion',
    OPERATIONS: 'system/operations'
});

const safeEqual = (left, right) => {
    const a = Buffer.from(String(left || ''));
    const b = Buffer.from(String(right || ''));
    return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const parseBasicAuth = (header) => {
    const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(String(header || '').trim());
    if (!match) return null;
    try {
        const decoded = Buffer.from(match[1], 'base64').toString('utf8');
        const splitAt = decoded.indexOf(':');
        if (splitAt < 1) return null;
        return { username: decoded.slice(0, splitAt), password: decoded.slice(splitAt + 1) };
    } catch { return null; }
};

const capabilityFor = (method, path) => {
    const verb = String(method || 'GET').toUpperCase();
    const route = String(path || '/');
    if (route.includes('deletion-request')) return ADMIN_CAPABILITIES.DELETION;
    if (route.includes('legal') || route.includes('notification')) return verb === 'GET' ? ADMIN_CAPABILITIES.READ : ADMIN_CAPABILITIES.CONTENT;
    if (route.includes('push/') || route.includes('performance') || route.includes('analytics') || route.includes('audit')) return ADMIN_CAPABILITIES.OPERATIONS;
    if (route.includes('profile-details') || route.includes('support-report') || route.includes('user-')) return ADMIN_CAPABILITIES.SENSITIVE_READ;
    return verb === 'GET' ? ADMIN_CAPABILITIES.READ : ADMIN_CAPABILITIES.ACTION;
};

const createAdminGuard = ({ windowMs = 10 * 60 * 1000, maxAttempts = 10 } = {}) => {
    const limiter = new BoundedRateLimiter({ windowMs, max: maxAttempts, maxKeys: 5000 });
    return (req, res, next) => {
        const key = hashKey('admin-ip', resolvePeerAddress(req));
        const parsed = parseBasicAuth(req.headers.authorization);
        const expectedUser = process.env.ADMIN_USER || 'admin';
        const expectedPassword = process.env.ADMIN_PASSWORD || 'admin123';
        const valid = parsed && safeEqual(parsed.username, expectedUser) && safeEqual(parsed.password, expectedPassword);
        if (!valid) {
            const limit = limiter.consume(key);
            if (!limit.allowed) {
                res.set('Retry-After', String(Math.max(1, Math.ceil(limit.retryAfterMs / 1000))));
                return res.status(429).json(buildErrorEnvelope({
                    errorCode: 'RATE_LIMITED', message: 'Too many admin authentication attempts.',
                    requestId: req.requestId, retryable: true, retryAfterMs: limit.retryAfterMs,
                    metadata: { policy: 'admin-auth' }
                }));
            }
            res.set('WWW-Authenticate', 'Basic realm="TalkX Admin", charset="UTF-8"');
            return res.status(401).json(buildErrorEnvelope({
                errorCode: 'ADMIN_AUTH_REQUIRED', message: 'Authentication required.', requestId: req.requestId
            }));
        }
        req.adminUser = parsed.username;
        req.adminCapability = capabilityFor(req.method, req.path);
        res.set('X-TalkX-Admin-Capability', req.adminCapability);
        return next();
    };
};

module.exports = { ADMIN_CAPABILITIES, capabilityFor, createAdminGuard, parseBasicAuth, safeEqual };
