const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
    applyDeadline,
    applyDecision,
    closePendingMatch,
    completePendingMatch,
    createPendingMatchRecord
} = require('../utils/pendingMatch');
const { rebindTransientParticipant, resolveTransientSnapshot } = require('../utils/transientRecovery');
const { validateWsEvent } = require('../utils/wave01Security');

const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const participants = () => ([
    { clientId: 'a', searchId: uuid(2), effectiveMatchScope: 'COUNTRY', country: { code: 'TR' }, username: 'Ada' },
    { clientId: 'b', searchId: uuid(3), effectiveMatchScope: 'COUNTRY', country: { code: 'TR' }, username: 'Bora' }
]);
const record = () => createPendingMatchRecord({
    id: uuid(1),
    participants: participants(),
    offeredAt: 1000,
    autoAcceptAt: 9000,
    timeoutMs: 8000
});

test('decision commands are idempotent and conflicting retries cannot alter state', () => {
    const pending = record();
    const first = applyDecision(pending, { participantId: 'a', decision: 'accept', commandId: uuid(4), searchId: uuid(2), now: 2000 });
    const replay = applyDecision(pending, { participantId: 'a', decision: 'accept', commandId: uuid(4), searchId: uuid(2), now: 3000 });
    const conflict = applyDecision(pending, { participantId: 'a', decision: 'pass', commandId: uuid(5), searchId: uuid(2), now: 4000 });
    assert.equal(first.kind, 'waiting');
    assert.equal(replay.replayed, true);
    assert.equal(conflict.kind, 'conflict');
    assert.equal(pending.participants[0].decision, 'accepted');
    assert.equal(pending.revision, 2);
});

test('manual and deadline acceptance race reaches finalizing exactly once', () => {
    const pending = record();
    applyDecision(pending, { participantId: 'a', decision: 'accept', commandId: uuid(4), searchId: uuid(2), now: 8000 });
    const deadline = applyDeadline(pending, { now: 9000 });
    const duplicate = applyDeadline(pending, { now: 9100 });
    assert.equal(deadline.kind, 'finalize');
    assert.deepEqual(deadline.changed.map((item) => item.clientId), ['b']);
    assert.equal(duplicate.kind, 'terminal');
    assert.equal(pending.status, 'finalizing');
    assert.equal(completePendingMatch(pending, { conversationId: uuid(6), now: 9200 }).kind, 'completed');
    assert.equal(completePendingMatch(pending, { conversationId: uuid(6), now: 9300 }).kind, 'replay');
});

test('pass closes the offer while cancel remains a distinct terminal reason', () => {
    const passed = record();
    assert.equal(applyDecision(passed, { participantId: 'a', decision: 'pass', commandId: uuid(4), searchId: uuid(2) }).kind, 'closed');
    assert.equal(passed.closeReason, 'passed');
    const cancelled = record();
    assert.equal(closePendingMatch(cancelled, 'user_cancelled').kind, 'closed');
    assert.equal(cancelled.closeReason, 'user_cancelled');
});

test('stale search identity and incomplete command identity fail closed', () => {
    const pending = record();
    assert.equal(applyDecision(pending, { participantId: 'a', decision: 'accept', commandId: uuid(4), searchId: uuid(99) }).kind, 'stale');
    assert.equal(validateWsEvent({ type: 'matchDecision', matchId: uuid(1), decision: 'pass', protocolVersion: 1, searchId: uuid(2) }).code, 'INVALID_INPUT');
    assert.equal(validateWsEvent({ type: 'matchDecision', matchId: uuid(1), decision: 'pass', protocolVersion: 1, searchId: uuid(2), commandId: uuid(4) }).ok, true);
    assert.equal(validateWsEvent({ type: 'matchOfferTelemetry', matchId: uuid(1), searchId: uuid(2), eventName: 'match_offer_rendered' }).ok, true);
});

test('recovery preserves participant aliases and returns privacy-safe canonical offer state', () => {
    const pending = record();
    const pendingMatches = new Map([[pending.id, pending]]);
    const userPendingMatchMap = new Map([['a', pending.id]]);
    const nextQueue = rebindTransientParticipant({
        previousConnectionId: 'a', connectionId: 'a2', ws: { readyState: 1 }, waitingQueue: [],
        pendingMatches, userPendingMatchMap, rooms: new Map(), userRoomMap: new Map()
    });
    assert.deepEqual(nextQueue, []);
    assert.equal(pending.users, pending.participants);
    const snapshot = resolveTransientSnapshot({
        connectionId: 'a2', waitingQueue: [], pendingMatches, userPendingMatchMap,
        rooms: new Map(), userRoomMap: new Map(), activeClients: new Map()
    });
    assert.equal(snapshot.kind, 'offer');
    assert.equal(snapshot.peerPublicLabel, 'Bora');
    assert.equal(snapshot.peerId, undefined);
    assert.equal(snapshot.peerUsername, undefined);
});

test('conversation creation is guarded by a unique match identity', () => {
    const dbSource = fs.readFileSync(path.join(__dirname, '..', 'db.js'), 'utf8');
    const serverSource = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    assert.match(dbSource, /ADD COLUMN IF NOT EXISTS match_id UUID/);
    assert.match(dbSource, /CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_match_id_unique/);
    assert.match(serverSource, /ON CONFLICT \(match_id\) WHERE match_id IS NOT NULL/);
    assert.match(serverSource, /pendingMatchV1/);
    assert.match(serverSource, /timingPolicyVersion: 'pending-match-timing-v1'/);
    assert.match(serverSource, /trigger: 'recovery_resume'/);
});
