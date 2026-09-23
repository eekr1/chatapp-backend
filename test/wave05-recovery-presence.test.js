const test = require('node:test');
const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const path = require('node:path');

process.env.DATABASE_URL ||= 'postgres://user:pass@localhost:5432/test';

const { RecoveryRegistry, buildRecoverySnapshot } = require('../utils/recoveryState');
const { createPresenceService, hashDevice } = require('../utils/presenceService');
const { resolveRealtimeRuntimeConfig } = require('../utils/runtimeConfig');
const { validateWsEvent } = require('../utils/wave01Security');
const { rebindTransientParticipant, resolveTransientSnapshot } = require('../utils/transientRecovery');

const identity = {
    userId: 'user-1', sessionId: 'session-hash-1', deviceId: 'device-1'
};

test('recovery lease resumes once, rotates token and supersedes the old connection', () => {
    let now = 1000;
    const timers = new Map();
    let nextTimer = 1;
    const registry = new RecoveryRegistry({
        enabled: true,
        graceMs: 5000,
        now: () => now,
        setTimer: (fn) => { const id = nextTimer++; timers.set(id, fn); return id; },
        clearTimer: (id) => timers.delete(id)
    });
    const first = registry.attach({ connectionId: 'connection-1', ...identity });
    assert.equal(first.result, 'fresh');
    assert.equal(registry.isCurrentConnection('connection-1'), true);
    let cleanupCount = 0;
    assert.equal(registry.detach('connection-1', () => { cleanupCount += 1; }), true);
    now += 1000;
    const resumed = registry.attach({
        connectionId: 'connection-2', recoveryToken: first.token,
        previousServerEpoch: registry.serverEpoch, ...identity
    });
    assert.equal(resumed.result, 'resumed');
    assert.equal(resumed.previousConnectionId, 'connection-1');
    assert.notEqual(resumed.token, first.token);
    assert.equal(registry.isCurrentConnection('connection-1'), false);
    assert.equal(registry.isCurrentConnection('connection-2'), true);
    assert.equal(cleanupCount, 0);
    assert.equal(timers.size, 0);
});

test('grace expiry performs cleanup exactly once and cannot be resumed', () => {
    let now = 1000;
    let timer;
    const registry = new RecoveryRegistry({
        enabled: true, graceMs: 5000, now: () => now,
        setTimer: (fn) => { timer = fn; return 1; }, clearTimer: () => {}
    });
    const first = registry.attach({ connectionId: 'connection-1', ...identity });
    let reason;
    registry.detach('connection-1', (value) => { reason = value; });
    now = 6000;
    timer();
    timer();
    assert.equal(reason, 'grace_expired');
    const reset = registry.attach({
        connectionId: 'connection-2', recoveryToken: first.token,
        previousServerEpoch: registry.serverEpoch, ...identity
    });
    assert.equal(reset.result, 'reset');
    assert.equal(reset.reason, 'invalid_token');
});

test('two-client queue, offer and room ownership rebinds to one new socket', () => {
    const oldWs = { name: 'old' };
    const newWs = { name: 'new' };
    const peerWs = { name: 'peer' };
    let waitingQueue = [{ clientId: 'old', ws: oldWs }, { clientId: 'peer', ws: peerWs }];
    const pendingMatches = new Map([['match-1', {
        autoAcceptAt: 5000, timeoutMs: 8000,
        users: [
            { clientId: 'old', ws: oldWs, decision: 'pending' },
            { clientId: 'peer', ws: peerWs, decision: 'accepted', nickname: 'Peer' }
        ]
    }]]);
    const userPendingMatchMap = new Map([['old', 'match-1'], ['peer', 'match-1']]);
    const rooms = new Map([['room-1', {
        users: [{ clientId: 'old' }, { clientId: 'peer', nickname: 'Peer' }],
        sockets: { old: oldWs, peer: peerWs }
    }]]);
    const userRoomMap = new Map([['old', 'room-1'], ['peer', 'room-1']]);

    waitingQueue = rebindTransientParticipant({
        previousConnectionId: 'old', connectionId: 'new', ws: newWs,
        waitingQueue, pendingMatches, userPendingMatchMap, rooms, userRoomMap
    });
    assert.equal(waitingQueue.filter((item) => item.clientId === 'new').length, 1);
    assert.equal(waitingQueue.some((item) => item.clientId === 'old'), false);
    assert.equal(userPendingMatchMap.get('new'), 'match-1');
    assert.equal(pendingMatches.get('match-1').users[0].ws, newWs);
    assert.equal(userRoomMap.get('new'), 'room-1');
    assert.equal(rooms.get('room-1').sockets.new, newWs);
    assert.equal(rooms.get('room-1').sockets.old, undefined);

    waitingQueue = [];
    const offer = resolveTransientSnapshot({
        connectionId: 'new', waitingQueue, pendingMatches, userPendingMatchMap,
        rooms: new Map(), userRoomMap: new Map(), activeClients: new Map([['peer', {}]])
    });
    assert.equal(offer.kind, 'offer');
    assert.equal(offer.matchId, 'match-1');
    const room = resolveTransientSnapshot({
        connectionId: 'new', waitingQueue, pendingMatches: new Map(), userPendingMatchMap: new Map(),
        rooms, userRoomMap, activeClients: new Map([['peer', {}]])
    });
    assert.equal(room.kind, 'anonymous_room');
    assert.equal(room.peerConnection, 'connected');
});

test('server epoch mismatch is an explicit restart reset and snapshot is bounded', () => {
    const registry = new RecoveryRegistry({ enabled: true, graceMs: 7000 });
    const recovery = registry.attach({
        connectionId: 'connection-1', recoveryToken: 'x'.repeat(43),
        previousServerEpoch: 'old-epoch', ...identity
    });
    assert.equal(recovery.reason, 'server_restart');
    const snapshot = buildRecoverySnapshot({
        recovery: { ...recovery, serverEpoch: registry.serverEpoch, graceMs: registry.graceMs },
        active: { kind: 'idle' }
    });
    assert.equal(snapshot.schemaVersion, 1);
    assert.equal(snapshot.result, 'reset');
    assert.equal(snapshot.active.kind, 'idle');
    assert.equal(snapshot.recoveryGraceMs, 7000);
    assert.ok(!JSON.stringify(snapshot).includes(identity.sessionId));
});

test('hello contract accepts bounded recovery metadata and rejects extra fields', () => {
    const valid = validateWsEvent({
        type: 'hello_ack', deviceId: 'd1', token: 'a'.repeat(32), platform: 'web',
        recoveryToken: 'b'.repeat(43), serverEpoch: 'epoch-1'
    });
    assert.equal(valid.ok, true);
    assert.equal(validateWsEvent({ ...valid.event, rawSession: 'secret' }).code, 'UNEXPECTED_FIELD');
});

test('realtime config clamps grace, heartbeat and lease and keeps topology explicit', () => {
    const config = resolveRealtimeRuntimeConfig({
        REALTIME_RECOVERY_ENABLED: 'true', RECOVERY_GRACE_MS: '1',
        PRESENCE_HEARTBEAT_MS: '999999', PRESENCE_LEASE_MS: '1',
        REALTIME_TOPOLOGY: 'unexpected', INSTANCE_ID: 'instance-a'
    });
    assert.equal(config.recoveryEnabled, true);
    assert.equal(config.recoveryGraceMs, 5000);
    assert.equal(config.presenceHeartbeatMs, 60000);
    assert.equal(config.presenceLeaseMs, 30000);
    assert.equal(config.topology, 'single');
    assert.equal(config.instanceId, 'instance-a');
});

test('presence open stores only hashed device identity and exposes transition result', async () => {
    const calls = [];
    const pool = {
        query: async (sql, params) => {
            calls.push([sql, params]);
            return { rows: [{ became_online: true }] };
        }
    };
    const service = createPresenceService({
        pool,
        config: { presenceLeaseMs: 90000, recoveryGraceMs: 15000, instanceId: 'instance-a' }
    });
    const opened = await service.open({ connectionId: 'c1', ...identity, generation: 1 });
    assert.equal(opened.becameOnline, true);
    assert.equal(calls[0][1][3], hashDevice(identity.deviceId));
    assert.notEqual(calls[0][1][3], identity.deviceId);
    assert.doesNotMatch(calls[0][0], /raw_token|recovery_token|ip_address/i);
});

test('presence final close preserves online when another device lease remains', async () => {
    const responses = [
        { rows: [] }, { rows: [{ user_id: 'user-1' }] }, { rows: [] }, { rows: [{ ok: 1 }] }, { rows: [] }
    ];
    const client = { query: async () => responses.shift() || { rows: [] }, release() {} };
    const service = createPresenceService({
        pool: { connect: async () => client },
        config: { presenceLeaseMs: 90000, recoveryGraceMs: 15000, instanceId: 'instance-a' }
    });
    const result = await service.closeFinal('connection-1');
    assert.equal(result.userId, 'user-1');
    assert.equal(result.becameOffline, false);
});

test('migration and friends query use shared leases without process-map fallback', async () => {
    const dbSource = await readFile(path.join(__dirname, '..', 'db.js'), 'utf8');
    const friendsSource = await readFile(path.join(__dirname, '..', 'routes', 'friends.js'), 'utf8');
    assert.match(dbSource, /version:\s*'002'/);
    assert.match(dbSource, /CREATE TABLE IF NOT EXISTS connection_leases/);
    assert.match(dbSource, /idx_connection_leases_user_expiry/);
    assert.match(friendsSource, /EXISTS\s*\([\s\S]*connection_leases/);
    assert.match(friendsSource, /presence_observed_at/);
    assert.doesNotMatch(friendsSource, /req\.isUserOnline/);
});
