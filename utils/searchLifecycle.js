const { randomUUID } = require('crypto');

const PROTOCOL_VERSION = 1;
const TIMING_POLICY_VERSION = 'match-search-timing-v1';
const TIER_THRESHOLDS_MS = Object.freeze({ continuing: 8000, quiet: 20000, extended: 45000 });
const ACTIVE_PHASES = new Set(['queued', 'extended', 'offer']);

const iso = (value) => new Date(value).toISOString();

const createSearchLifecycle = ({
    now = () => Date.now(),
    setTimer = (fn, ms) => setTimeout(fn, ms),
    clearTimer = (timer) => clearTimeout(timer),
    onPhase = () => {}
} = {}) => {
    const byUser = new Map();
    const byConnection = new Map();
    const commandResults = new Map();
    const timers = new Map();

    const envelope = (record, extra = {}) => ({
        protocolVersion: PROTOCOL_VERSION,
        searchId: record.searchId,
        queueAttempt: record.queueAttempt,
        searchStartedAt: record.searchStartedAt,
        queuedAt: record.queuedAt,
        serverNow: iso(now()),
        phase: record.phase,
        timingPolicyVersion: TIMING_POLICY_VERSION,
        tierThresholdsMs: TIER_THRESHOLDS_MS,
        searchRevision: record.revision,
        ...extra
    });

    const clearExtendedTimer = (searchId) => {
        const timer = timers.get(searchId);
        if (timer) clearTimer(timer);
        timers.delete(searchId);
    };

    const scheduleExtended = (record) => {
        clearExtendedTimer(record.searchId);
        const due = Math.max(0, new Date(record.queuedAt).getTime() + TIER_THRESHOLDS_MS.extended - now());
        const timer = setTimer(() => {
            const current = byUser.get(record.userId);
            if (!current || current.searchId !== record.searchId || current.queueAttempt !== record.queueAttempt || current.phase !== 'queued') return;
            current.phase = 'extended';
            current.updatedAt = iso(now());
            current.revision += 1;
            onPhase(current, envelope(current, { type: 'search_phase', effectiveAt: current.updatedAt, reasonCode: 'long_wait' }));
        }, due);
        timers.set(record.searchId, timer);
    };

    const rememberCommand = (userId, commandId, result) => {
        if (!commandId) return;
        commandResults.set(`${userId}:${commandId}`, result);
        if (commandResults.size > 1000) commandResults.delete(commandResults.keys().next().value);
    };

    const begin = ({ userId, connectionId, searchId = randomUUID(), commandId = randomUUID() }) => {
        const existingCommand = commandResults.get(`${userId}:${commandId}`);
        if (existingCommand) return { ...existingCommand, replayed: true };
        const current = byUser.get(userId);
        if (current && ACTIVE_PHASES.has(current.phase)) {
            if (current.searchId !== searchId) {
            const result = { kind: 'conflict', record: current, event: envelope(current, { type: 'search_error', errorCode: 'SEARCH_ALREADY_ACTIVE', commandId, retryable: false, localeKey: 'errors.SEARCH_ALREADY_ACTIVE' }) };
                rememberCommand(userId, commandId, result);
                return result;
            }
            const result = { kind: 'replay', record: current, event: envelope(current, { type: current.phase === 'offer' ? 'search_phase' : 'queued', commandId, replayed: true }) };
            rememberCommand(userId, commandId, result);
            return result;
        }
        const timestamp = iso(now());
        const record = {
            userId, connectionId, searchId, phase: 'queued', queueAttempt: 1,
            searchStartedAt: timestamp, queuedAt: timestamp, createdAt: timestamp, updatedAt: timestamp,
            revision: 1, terminalReason: null
        };
        byUser.set(userId, record);
        byConnection.set(connectionId, record);
        scheduleExtended(record);
        const result = { kind: 'accepted', record, event: envelope(record, { type: 'queued', commandId, replayed: false }) };
        rememberCommand(userId, commandId, result);
        return result;
    };

    const requeue = ({ connectionId }) => {
        const record = byConnection.get(connectionId);
        if (!record || !ACTIVE_PHASES.has(record.phase)) return null;
        record.phase = 'queued';
        record.queueAttempt += 1;
        record.queuedAt = iso(now());
        record.updatedAt = record.queuedAt;
        record.revision += 1;
        scheduleExtended(record);
        return { record, event: envelope(record, { type: 'queued', replayed: false, reasonCode: 'requeue' }) };
    };

    const markOffer = (connectionId) => {
        const record = byConnection.get(connectionId);
        if (!record || !ACTIVE_PHASES.has(record.phase)) return null;
        clearExtendedTimer(record.searchId);
        record.phase = 'offer';
        record.updatedAt = iso(now());
        record.revision += 1;
        return envelope(record);
    };

    const cancel = ({ userId, connectionId, searchId, commandId = randomUUID(), reason = 'user_cancelled' }) => {
        const existingCommand = commandResults.get(`${userId}:${commandId}`);
        if (existingCommand) return { ...existingCommand, replayed: true };
        const record = byConnection.get(connectionId) || byUser.get(userId);
        if (!record || record.searchId !== searchId || !ACTIVE_PHASES.has(record.phase)) {
            const result = { kind: 'stale', record, event: { type: 'queue_left', protocolVersion: PROTOCOL_VERSION, searchId, commandId, result: 'stale', serverNow: iso(now()) } };
            rememberCommand(userId, commandId, result);
            return result;
        }
        clearExtendedTimer(record.searchId);
        record.phase = 'cancelled';
        record.terminalReason = reason;
        record.updatedAt = iso(now());
        record.revision += 1;
        const result = { kind: 'cancelled', record, event: envelope(record, { type: 'queue_left', commandId, result: 'cancelled', reasonCode: reason }) };
        rememberCommand(userId, commandId, result);
        return result;
    };

    const terminate = (connectionId, reason = 'terminal') => {
        const record = byConnection.get(connectionId);
        if (!record) return null;
        clearExtendedTimer(record.searchId);
        if (ACTIVE_PHASES.has(record.phase)) {
            record.phase = 'cancelled';
            record.terminalReason = reason;
            record.updatedAt = iso(now());
            record.revision += 1;
        }
        byConnection.delete(connectionId);
        return record;
    };

    const rebind = (previousConnectionId, connectionId) => {
        const record = byConnection.get(previousConnectionId);
        if (!record) return null;
        byConnection.delete(previousConnectionId);
        record.connectionId = connectionId;
        byConnection.set(connectionId, record);
        return record;
    };

    return {
        begin, requeue, markOffer, cancel, terminate, rebind,
        getByConnection: (connectionId) => byConnection.get(connectionId) || null,
        getByUser: (userId) => byUser.get(userId) || null,
        envelope,
        constants: { PROTOCOL_VERSION, TIMING_POLICY_VERSION, TIER_THRESHOLDS_MS }
    };
};

module.exports = { createSearchLifecycle, PROTOCOL_VERSION, TIMING_POLICY_VERSION, TIER_THRESHOLDS_MS };
