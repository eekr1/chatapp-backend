const { v4: uuidv4 } = require('uuid');

const CONTRACT_VERSION = '1';
const CAPABILITIES = Object.freeze({
    apiErrorEnvelope: 1,
    sessionLogoutAll: 1,
    wsAuthenticatedIdentity: 1,
    wsRateLimitRetry: 1
});

const safeRequestId = (value) => {
    const candidate = String(value || '').trim();
    return /^[A-Za-z0-9._:-]{1,120}$/.test(candidate) ? candidate : uuidv4();
};

const serverTime = () => new Date().toISOString();

const requestContext = (req, res, next) => {
    req.requestId = safeRequestId(req.get?.('x-request-id'));
    res.setHeader('X-Request-ID', req.requestId);
    res.setHeader('X-TalkX-Contract-Version', CONTRACT_VERSION);
    next();
};

const buildErrorEnvelope = ({
    errorCode = 'SERVER_ERROR',
    message = 'Server error.',
    requestId = null,
    retryable = false,
    retryAfterMs = null,
    metadata = null
} = {}) => {
    const body = {
        schemaVersion: CONTRACT_VERSION,
        errorCode,
        message,
        retryable: Boolean(retryable),
        requestId: requestId || null,
        serverTime: serverTime(),
        // Compatibility aliases for supported pre-Wave-02 clients.
        code: errorCode,
        error: message
    };
    if (Number.isFinite(retryAfterMs) && retryAfterMs >= 0) body.retryAfterMs = Math.ceil(retryAfterMs);
    if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)) body.metadata = metadata;
    return body;
};

const buildSuccessMeta = (requestId = null) => ({
    schemaVersion: CONTRACT_VERSION,
    requestId: requestId || null,
    serverTime: serverTime(),
    capabilities: CAPABILITIES
});

module.exports = {
    CAPABILITIES,
    CONTRACT_VERSION,
    buildErrorEnvelope,
    buildSuccessMeta,
    requestContext,
    safeRequestId,
    serverTime
};
