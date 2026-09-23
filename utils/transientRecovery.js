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
    if (waitingQueue.some((item) => item.clientId === connectionId)) return { kind: 'queue' };
    const matchId = userPendingMatchMap.get(connectionId);
    const pending = matchId ? pendingMatches.get(matchId) : null;
    if (pending) {
        const participant = pending.users.find((item) => item.clientId === connectionId);
        const peer = pending.users.find((item) => item.clientId !== connectionId);
        return {
            kind: 'offer', matchId,
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
