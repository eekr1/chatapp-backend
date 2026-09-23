const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const RECOVERY_REASONS = new Set([
    'none', 'grace_expired', 'server_restart', 'state_missing', 'invalid_token', 'superseded'
]);

const createRecoveryToken = () => crypto.randomBytes(32).toString('base64url');

class RecoveryRegistry {
    constructor({ graceMs = 15000, enabled = false, now = () => Date.now(), setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
        this.graceMs = graceMs;
        this.enabled = enabled;
        this.now = now;
        this.setTimer = setTimer;
        this.clearTimer = clearTimer;
        this.serverEpoch = uuidv4();
        this.leases = new Map();
        this.byConnection = new Map();
    }

    attach({ connectionId, userId, sessionId, deviceId, recoveryToken, previousServerEpoch }) {
        let prior = recoveryToken ? this.leases.get(recoveryToken) : null;
        let result = 'fresh';
        let reason = 'none';
        let previousConnectionId = null;

        if (this.enabled && recoveryToken) {
            if (!prior) {
                result = 'reset';
                reason = previousServerEpoch && previousServerEpoch !== this.serverEpoch
                    ? 'server_restart'
                    : 'invalid_token';
            } else if (prior.userId !== userId || prior.sessionId !== sessionId || prior.deviceId !== deviceId) {
                result = 'reset';
                reason = 'invalid_token';
                prior = null;
            } else if (prior.expiresAt && prior.expiresAt <= this.now()) {
                this.expire(prior.token, 'grace_expired');
                result = 'reset';
                reason = 'grace_expired';
                prior = null;
            } else {
                result = 'resumed';
                previousConnectionId = prior.connectionId;
            }
        }

        const token = createRecoveryToken();
        const lease = prior || {
            participantId: uuidv4(),
            userId,
            sessionId,
            deviceId,
            generation: 0,
            stateRevision: 0,
            cleanup: null,
            timer: null
        };
        if (lease.timer) this.clearTimer(lease.timer);
        if (prior) this.leases.delete(prior.token);
        if (previousConnectionId) this.byConnection.delete(previousConnectionId);
        lease.token = token;
        lease.connectionId = connectionId;
        lease.generation += 1;
        lease.detached = false;
        lease.expiresAt = null;
        lease.cleanup = null;
        lease.timer = null;
        this.leases.set(token, lease);
        this.byConnection.set(connectionId, lease);

        return { lease, token, result, reason, previousConnectionId };
    }

    detach(connectionId, cleanup) {
        const lease = this.byConnection.get(connectionId);
        if (!lease || lease.connectionId !== connectionId || lease.detached) return false;
        lease.detached = true;
        lease.expiresAt = this.now() + this.graceMs;
        lease.cleanup = cleanup;
        lease.timer = this.setTimer(() => this.expire(lease.token, 'grace_expired'), this.graceMs);
        return true;
    }

    expire(token, reason = 'grace_expired') {
        const lease = this.leases.get(token);
        if (!lease) return false;
        if (lease.timer) this.clearTimer(lease.timer);
        this.leases.delete(token);
        this.byConnection.delete(lease.connectionId);
        const cleanup = lease.cleanup;
        lease.cleanup = null;
        lease.timer = null;
        if (typeof cleanup === 'function') cleanup(reason, lease);
        return true;
    }

    isCurrentConnection(connectionId) {
        const lease = this.byConnection.get(connectionId);
        return Boolean(lease && lease.connectionId === connectionId && !lease.detached);
    }

    getByConnection(connectionId) {
        return this.byConnection.get(connectionId) || null;
    }

    bump(connectionId) {
        const lease = this.getByConnection(connectionId);
        if (!lease) return 0;
        lease.stateRevision += 1;
        return lease.stateRevision;
    }
}

const normalizeRecoveryReason = (value) => RECOVERY_REASONS.has(value) ? value : 'state_missing';

const buildRecoverySnapshot = ({ recovery, active = { kind: 'idle' }, unread = { friends: [], system: 0, revision: 0 }, partial = false, serverNow = new Date().toISOString() }) => ({
    type: 'recovery_snapshot',
    schemaVersion: 1,
    connectionId: recovery.lease.connectionId,
    serverEpoch: recovery.serverEpoch,
    serverNow,
    result: recovery.result,
    reason: normalizeRecoveryReason(recovery.reason),
    recoveryGraceMs: recovery.graceMs,
    stateRevision: recovery.lease.stateRevision,
    active,
    unread,
    partial: Boolean(partial),
    recoveryToken: recovery.token
});

module.exports = { RecoveryRegistry, buildRecoverySnapshot, normalizeRecoveryReason };
