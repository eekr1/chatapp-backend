const rebindTransientParticipant = ({
    previousConnectionId, connectionId, ws, waitingQueue,
    pendingMatches, userPendingMatchMap, rooms, userRoomMap
}) => {
    const nextQueue = waitingQueue.map((item) => item.clientId === previousConnectionId
        ? { ...item, clientId: connectionId, ws }
        : item);
    const matchId = userPendingMatchMap.get(previousConnectionId);
    if (matchId) {
        const pending = pendingMatches.get(matchId);
        if (pending) {
            pending.users = pending.users.map((participant) => participant.clientId === previousConnectionId
                ? { ...participant, clientId: connectionId, ws }
                : participant);
        }
        userPendingMatchMap.delete(previousConnectionId);
        userPendingMatchMap.set(connectionId, matchId);
    }
    const roomId = userRoomMap.get(previousConnectionId);
    if (roomId) {
        const room = rooms.get(roomId);
        if (room) {
            room.users = room.users.map((participant) => participant.clientId === previousConnectionId
                ? { ...participant, clientId: connectionId }
                : participant);
            delete room.sockets[previousConnectionId];
            room.sockets[connectionId] = ws;
        }
        userRoomMap.delete(previousConnectionId);
        userRoomMap.set(connectionId, roomId);
    }
    return nextQueue;
};

const resolveTransientSnapshot = ({
    connectionId, waitingQueue, pendingMatches, userPendingMatchMap,
    rooms, userRoomMap, activeClients
}) => {
    const queueEntry = waitingQueue.find((item) => item.clientId === connectionId);
    if (queueEntry) return {
        kind: 'queue',
        protocolVersion: 1,
        searchId: queueEntry.searchId,
        queueAttempt: queueEntry.queueAttempt,
        searchStartedAt: queueEntry.searchStartedAt,
        queuedAt: queueEntry.queuedAt,
        serverNow: new Date().toISOString(),
        phase: queueEntry.phase || 'queued',
        searchRevision: queueEntry.searchRevision || 1,
        queuePreserved: true,
        timingPolicyVersion: 'match-search-timing-v1',
        tierThresholdsMs: { continuing: 8000, quiet: 20000, extended: 45000 }
    };
    const matchId = userPendingMatchMap.get(connectionId);
    const pending = matchId ? pendingMatches.get(matchId) : null;
    if (pending) {
        const participant = pending.users.find((item) => item.clientId === connectionId);
        const peer = pending.users.find((item) => item.clientId !== connectionId);
        return {
            kind: 'offer', matchId,
            protocolVersion: 1,
            searchId: participant?.searchId || null,
            queueAttempt: participant?.queueAttempt || 1,
            phase: 'offer',
            decision: participant?.decision || 'pending',
            autoAcceptAt: pending.autoAcceptAt,
            timeoutMs: pending.timeoutMs,
            peerNickname: peer?.nickname || null,
            peerUsername: peer?.username || null,
            peerId: peer?.dbUserId || null
        };
    }
    const roomId = userRoomMap.get(connectionId);
    const room = roomId ? rooms.get(roomId) : null;
    if (room) {
        const peer = room.users.find((item) => item.clientId !== connectionId);
        return {
            kind: 'anonymous_room', roomId,
            peerNickname: peer?.nickname || null,
            peerUsername: peer?.username || null,
            peerId: peer?.dbUserId || null,
            peerConnection: peer && activeClients.has(peer.clientId) ? 'connected' : 'reconnecting'
        };
    }
    return { kind: 'idle' };
};

module.exports = { rebindTransientParticipant, resolveTransientSnapshot };
