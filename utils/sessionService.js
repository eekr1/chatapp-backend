const { pool } = require('../db');
const { generateSessionToken, hashToken } = require('./security');

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const revokeListeners = new Set();

const normalizeDeviceId = (value) => {
    const clean = String(value || 'unknown').trim().slice(0, 200);
    return clean || 'unknown';
};

const parseBearerToken = (header) => {
    const match = /^Bearer\s+([^\s]+)$/i.exec(String(header || '').trim());
    return match ? match[1] : null;
};

const findValidSessionByToken = async (token, db = pool) => {
    if (!token) return null;
    const tokenHash = hashToken(token);
    const result = await db.query(
        `SELECT s.token_hash, s.user_id, s.device_id, s.expires_at,
                u.username, u.status, p.display_name, p.locale
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         LEFT JOIN profiles p ON p.user_id = u.id
         WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
        [tokenHash]
    );
    return result.rows[0] || null;
};

const createSession = async ({ userId, deviceId }, db = pool) => {
    const normalizedDeviceId = normalizeDeviceId(deviceId);
    const token = generateSessionToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    const client = typeof db.connect === 'function' ? await db.connect() : db;
    const ownsClient = client !== db;
    let replacedSessions = [];
    try {
        await client.query('BEGIN');
        // A login retry for the same user/device replaces, rather than duplicates, its session.
        const replaced = await client.query(
            'DELETE FROM sessions WHERE user_id = $1 AND device_id = $2 RETURNING token_hash, user_id, device_id',
            [userId, normalizedDeviceId]
        );
        replacedSessions = replaced.rows || [];
        await client.query(
            'INSERT INTO sessions (token_hash, user_id, device_id, expires_at) VALUES ($1, $2, $3, $4)',
            [tokenHash, userId, normalizedDeviceId, expiresAt]
        );
        await client.query('COMMIT');
        if (replacedSessions.length) notifyRevoked(replacedSessions, 'session_replaced');
        return { token, tokenHash, expiresAt, deviceId: normalizedDeviceId };
    } catch (error) {
        try { await client.query('ROLLBACK'); } catch { /* best effort */ }
        throw error;
    } finally {
        if (ownsClient) client.release();
    }
};

const notifyRevoked = (sessions, reason) => {
    for (const listener of revokeListeners) listener(sessions, reason);
};

const revokeWhere = async (whereSql, params, reason, db = pool) => {
    const result = await db.query(`DELETE FROM sessions ${whereSql} RETURNING token_hash, user_id, device_id`, params);
    const sessions = result.rows || [];
    if (sessions.length) notifyRevoked(sessions, reason);
    return sessions;
};

const revokeCurrent = (token, reason = 'logout', db = pool) => {
    if (!token) return Promise.resolve([]);
    return revokeWhere('WHERE token_hash = $1', [hashToken(token)], reason, db);
};
const revokeAllForUser = (userId, reason = 'logout_all', db = pool) => (
    revokeWhere('WHERE user_id = $1', [userId], reason, db)
);
const onSessionsRevoked = (listener) => {
    revokeListeners.add(listener);
    return () => revokeListeners.delete(listener);
};

const authenticate = async (req, res, next) => {
    const { sendApiError } = require('./i18n');
    const token = parseBearerToken(req.headers.authorization);
    if (!token) return sendApiError(req, res, 401, 'AUTH_REQUIRED');
    try {
        const session = await findValidSessionByToken(token);
        if (!session) return sendApiError(req, res, 401, 'AUTH_INVALID');
        if (session.status !== 'active') return sendApiError(req, res, 403, 'ACCOUNT_INACTIVE');
        req.authToken = token;
        req.user = session;
        req.userId = session.user_id;
        return next();
    } catch {
        return sendApiError(req, res, 500, 'SERVER_ERROR');
    }
};

module.exports = {
    SESSION_TTL_MS,
    authenticate,
    createSession,
    findValidSessionByToken,
    normalizeDeviceId,
    onSessionsRevoked,
    parseBearerToken,
    revokeAllForUser,
    revokeCurrent
};
