const { WebSocket } = require('ws');
const { v4: uuidv4 } = require('uuid');
const { CONTRACT_VERSION, serverTime } = require('./contracts');

const MAX_BUFFERED_BYTES = 512 * 1024;
const PHASES = Object.freeze({
    CONNECTED: 'connected_untrusted',
    AUTHENTICATING: 'authenticating',
    AUTHENTICATED: 'authenticated',
    CLOSING: 'closing',
    CLOSED: 'closed'
});

const normalizeClientContext = (data = {}) => ({
    deviceId: String(data.deviceId || 'unknown').trim().slice(0, 200) || 'unknown',
    platform: ['web', 'android'].includes(data.platform) ? data.platform : 'web',
    locale: ['tr', 'en'].includes(data.lang) ? data.lang : 'en',
    release: String(data.appVersion || data.version || 'unknown').trim().slice(0, 60) || 'unknown',
    capabilities: Array.isArray(data.capabilities)
        ? data.capabilities.filter((item) => typeof item === 'string').map((item) => item.slice(0, 60)).slice(0, 30)
        : []
});

const safeSend = (ws, payload, { maxBufferedBytes = MAX_BUFFERED_BYTES } = {}) => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return { ok: false, reason: 'not_open' };
    if (Number(ws.bufferedAmount) > maxBufferedBytes) {
        ws.close(1013, 'Backpressure');
        return { ok: false, reason: 'backpressure' };
    }
    const body = {
        schemaVersion: CONTRACT_VERSION,
        serverTime: serverTime(),
        eventId: uuidv4(),
        ...payload
    };
    ws.send(JSON.stringify(body));
    return { ok: true, body };
};

class ConnectionRegistry {
    constructor() {
        this.connections = new Map();
        this.bySession = new Map();
    }

    connect(ws, connectionId) {
        const entry = { ws, connectionId, phase: PHASES.CONNECTED };
        this.connections.set(connectionId, entry);
        return entry;
    }

    beginAuthentication(connectionId) {
        const entry = this.connections.get(connectionId);
        if (!entry || entry.phase !== PHASES.CONNECTED) return false;
        entry.phase = PHASES.AUTHENTICATING;
        return true;
    }

    authenticate(connectionId, identity) {
        const entry = this.connections.get(connectionId);
        if (!entry || entry.phase !== PHASES.AUTHENTICATING) return false;
        Object.assign(entry, identity, { phase: PHASES.AUTHENTICATED });
        if (!this.bySession.has(identity.sessionId)) this.bySession.set(identity.sessionId, new Set());
        this.bySession.get(identity.sessionId).add(connectionId);
        return true;
    }

    isAuthenticated(connectionId) {
        return this.connections.get(connectionId)?.phase === PHASES.AUTHENTICATED;
    }

    get(connectionId) {
        return this.connections.get(connectionId) || null;
    }

    close(connectionId) {
        const entry = this.connections.get(connectionId);
        if (!entry) return null;
        entry.phase = PHASES.CLOSED;
        this.connections.delete(connectionId);
        if (entry.sessionId && this.bySession.has(entry.sessionId)) {
            const ids = this.bySession.get(entry.sessionId);
            ids.delete(connectionId);
            if (!ids.size) this.bySession.delete(entry.sessionId);
        }
        return entry;
    }

    closeSessions(sessions, reason = 'session_revoked') {
        for (const session of sessions || []) {
            const ids = [...(this.bySession.get(session.token_hash) || [])];
            for (const id of ids) {
                const entry = this.connections.get(id);
                if (!entry) continue;
                entry.phase = PHASES.CLOSING;
                safeSend(entry.ws, { type: 'error', errorCode: 'SESSION_REVOKED', code: 'SESSION_REVOKED', message: 'Session revoked.', retryable: false });
                entry.ws.close(1008, String(reason).slice(0, 120));
            }
        }
    }
}

module.exports = { ConnectionRegistry, MAX_BUFFERED_BYTES, PHASES, normalizeClientContext, safeSend };
