const DECISIONS = Object.freeze({ PENDING: 'pending', ACCEPTED: 'accepted', PASSED: 'passed' });
const STATUSES = Object.freeze({
    OFFERED: 'offered',
    WAITING: 'waiting',
    FINALIZING: 'finalizing',
    COMPLETED: 'completed',
    CLOSED: 'closed'
});
const TERMINAL_STATUSES = new Set([STATUSES.COMPLETED, STATUSES.CLOSED]);

const snapshot = (record) => ({
    matchId: record.id,
    status: record.status,
    revision: record.revision,
    offeredAt: record.offeredAt,
    autoAcceptAt: record.autoAcceptAt,
    closeReason: record.closeReason || null,
    conversationId: record.conversationId || null
});

const createPendingMatchRecord = ({ id, participants, offeredAt, autoAcceptAt, timeoutMs }) => {
    const normalizedParticipants = participants.map((participant) => ({
        ...participant,
        decision: DECISIONS.PENDING,
        decisionSource: null,
        decisionCommandId: null,
        decidedAt: null,
        offerRenderedAt: null
    }));
    return {
        id,
        status: STATUSES.OFFERED,
        revision: 1,
        offeredAt,
        autoAcceptAt,
        timeoutMs,
        participants: normalizedParticipants,
        users: normalizedParticipants,
        commandResults: new Map(),
        closeReason: null,
        conversationId: null,
        finalizedAt: null,
        timer: null
    };
};

const participantFor = (record, participantId) => record.participants
    .find((participant) => participant.clientId === participantId) || null;

const remember = (record, commandId, result) => {
    if (commandId) record.commandResults.set(commandId, result);
    return result;
};

const applyDecision = (record, {
    participantId,
    decision,
    commandId,
    searchId,
    now = Date.now(),
    source = 'manual'
}) => {
    const replay = commandId ? record.commandResults.get(commandId) : null;
    if (replay) return { ...replay, replayed: true };
    if (TERMINAL_STATUSES.has(record.status) || record.status === STATUSES.FINALIZING) {
        return remember(record, commandId, { kind: 'terminal', participant: null, record: snapshot(record) });
    }
    const participant = participantFor(record, participantId);
    if (!participant || (searchId && participant.searchId !== searchId)) {
        return remember(record, commandId, { kind: 'stale', participant: null, record: snapshot(record) });
    }
    const normalized = decision === 'reject' ? 'pass' : decision;
    const nextDecision = normalized === 'accept' ? DECISIONS.ACCEPTED : DECISIONS.PASSED;
    if (participant.decision !== DECISIONS.PENDING) {
        const same = participant.decision === nextDecision;
        return remember(record, commandId, {
            kind: same ? 'already_decided' : 'conflict',
            participant,
            record: snapshot(record)
        });
    }

    participant.decision = nextDecision;
    participant.decisionSource = source;
    participant.decisionCommandId = commandId || null;
    participant.decidedAt = new Date(now).toISOString();
    record.revision += 1;

    if (nextDecision === DECISIONS.PASSED) {
        record.status = STATUSES.CLOSED;
        record.closeReason = 'passed';
        return remember(record, commandId, { kind: 'closed', participant, record: snapshot(record) });
    }

    const allAccepted = record.participants.every((item) => item.decision === DECISIONS.ACCEPTED);
    record.status = allAccepted ? STATUSES.FINALIZING : STATUSES.WAITING;
    return remember(record, commandId, {
        kind: allAccepted ? 'finalize' : 'waiting',
        participant,
        record: snapshot(record)
    });
};

const applyDeadline = (record, { now = Date.now() } = {}) => {
    if (TERMINAL_STATUSES.has(record.status) || record.status === STATUSES.FINALIZING) {
        return { kind: 'terminal', changed: [], record: snapshot(record) };
    }
    if (now < record.autoAcceptAt) return { kind: 'early', changed: [], record: snapshot(record) };
    const changed = [];
    for (const participant of record.participants) {
        if (participant.decision !== DECISIONS.PENDING) continue;
        participant.decision = DECISIONS.ACCEPTED;
        participant.decisionSource = 'auto';
        participant.decisionCommandId = `deadline:${record.id}:${participant.clientId}`;
        participant.decidedAt = new Date(now).toISOString();
        changed.push(participant);
    }
    if (changed.length === 0) return { kind: 'terminal', changed, record: snapshot(record) };
    record.revision += 1;
    record.status = record.participants.every((item) => item.decision === DECISIONS.ACCEPTED)
        ? STATUSES.FINALIZING
        : STATUSES.WAITING;
    return {
        kind: record.status === STATUSES.FINALIZING ? 'finalize' : 'waiting',
        changed,
        record: snapshot(record)
    };
};

const closePendingMatch = (record, reason, { allowFinalizing = false } = {}) => {
    if (TERMINAL_STATUSES.has(record.status)) return { kind: 'terminal', record: snapshot(record) };
    if (record.status === STATUSES.FINALIZING && !allowFinalizing) return { kind: 'conflict', record: snapshot(record) };
    record.status = STATUSES.CLOSED;
    record.closeReason = String(reason || 'cancelled').slice(0, 80);
    record.revision += 1;
    return { kind: 'closed', record: snapshot(record) };
};

const completePendingMatch = (record, { conversationId, now = Date.now() }) => {
    if (record.status === STATUSES.COMPLETED) return { kind: 'replay', record: snapshot(record) };
    if (record.status !== STATUSES.FINALIZING) return { kind: 'conflict', record: snapshot(record) };
    record.status = STATUSES.COMPLETED;
    record.conversationId = conversationId;
    record.finalizedAt = new Date(now).toISOString();
    record.revision += 1;
    return { kind: 'completed', record: snapshot(record) };
};

const markOfferRendered = (record, participantId, now = Date.now()) => {
    const participant = participantFor(record, participantId);
    if (!participant || participant.offerRenderedAt) return false;
    participant.offerRenderedAt = new Date(now).toISOString();
    return true;
};

module.exports = {
    DECISIONS,
    STATUSES,
    applyDeadline,
    applyDecision,
    closePendingMatch,
    completePendingMatch,
    createPendingMatchRecord,
    markOfferRendered,
    participantFor,
    snapshot
};
