const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createSearchLifecycle } = require('../utils/searchLifecycle');
const { validateWsEvent } = require('../utils/wave01Security');

const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

test('join is identity-bound, ack-timed and duplicate command replays one queue record', () => {
    let now = Date.parse('2026-09-24T10:00:00Z');
    const lifecycle = createSearchLifecycle({ now: () => now, setTimer: () => 1, clearTimer() {} });
    const first = lifecycle.begin({ userId: 'u1', connectionId: 'c1', searchId: id(1), commandId: id(2) });
    assert.equal(first.kind, 'accepted');
    assert.equal(first.event.phase, 'queued');
    assert.equal(first.event.queuedAt, '2026-09-24T10:00:00.000Z');
    now += 500;
    const replay = lifecycle.begin({ userId: 'u1', connectionId: 'c1', searchId: id(1), commandId: id(2) });
    assert.equal(replay.replayed, true);
    assert.equal(replay.record, first.record);
    const conflict = lifecycle.begin({ userId: 'u1', connectionId: 'c1', searchId: id(3), commandId: id(4) });
    assert.equal(conflict.kind, 'conflict');
});

test('cancel is current-search guarded, idempotent and prevents revival', () => {
    const lifecycle = createSearchLifecycle({ setTimer: () => 1, clearTimer() {} });
    lifecycle.begin({ userId: 'u1', connectionId: 'c1', searchId: id(1), commandId: id(2) });
    const stale = lifecycle.cancel({ userId: 'u1', connectionId: 'c1', searchId: id(9), commandId: id(8) });
    assert.equal(stale.kind, 'stale');
    assert.equal(lifecycle.getByConnection('c1').phase, 'queued');
    const closed = lifecycle.cancel({ userId: 'u1', connectionId: 'c1', searchId: id(1), commandId: id(5) });
    assert.equal(closed.kind, 'cancelled');
    assert.equal(closed.event.result, 'cancelled');
    const replay = lifecycle.cancel({ userId: 'u1', connectionId: 'c1', searchId: id(1), commandId: id(5) });
    assert.equal(replay.replayed, true);
    assert.equal(lifecycle.requeue({ connectionId: 'c1' }), null);
});

test('requeue preserves journey and advances attempt while offer stops queue timer', () => {
    let cleared = 0;
    const lifecycle = createSearchLifecycle({ setTimer: () => 7, clearTimer: () => { cleared += 1; } });
    lifecycle.begin({ userId: 'u1', connectionId: 'c1', searchId: id(1), commandId: id(2) });
    const offer = lifecycle.markOffer('c1');
    assert.equal(offer.phase, 'offer');
    const requeued = lifecycle.requeue({ connectionId: 'c1' });
    assert.equal(requeued.record.searchId, id(1));
    assert.equal(requeued.event.queueAttempt, 2);
    assert.ok(cleared >= 1);
});

test('recovery rebind keeps the same search identity', () => {
    const lifecycle = createSearchLifecycle({ setTimer: () => 1, clearTimer() {} });
    lifecycle.begin({ userId: 'u1', connectionId: 'old', searchId: id(1), commandId: id(2) });
    lifecycle.rebind('old', 'new');
    assert.equal(lifecycle.getByConnection('old'), null);
    assert.equal(lifecycle.getByConnection('new').searchId, id(1));
});

test('Wave 07 websocket lifecycle identity remains strict after scope extension', () => {
    assert.equal(validateWsEvent({ type: 'joinQueue', protocolVersion: 1, searchId: id(1), commandId: id(2) }).ok, true);
    assert.equal(validateWsEvent({ type: 'leaveQueue', protocolVersion: 1, searchId: id(1), commandId: id(2), reason: 'user_cancelled' }).ok, true);
    assert.equal(validateWsEvent({ type: 'joinQueue', protocolVersion: 1, searchId: id(1), commandId: id(2), scope: 'COUNTRY' }).ok, true);
    assert.equal(validateWsEvent({ type: 'joinQueue', protocolVersion: 1, searchId: id(1), commandId: id(2), countryCode: 'TR' }).code, 'UNEXPECTED_FIELD');
    assert.equal(validateWsEvent({ type: 'joinQueue', searchId: id(1) }).code, 'INVALID_INPUT');
});

test('integration source still emits identified queue/offer/cancel after Wave 08', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
    const lifecycleSource = fs.readFileSync(path.join(__dirname, '..', 'utils', 'searchLifecycle.js'), 'utf8');
    assert.match(source, /matchSearchLifecycleV1/);
    assert.match(source, /searchLifecycle\.begin/);
    assert.match(source, /searchLifecycle\.cancel/);
    assert.match(source, /isCurrentQueueSearch/);
    assert.match(source, /currentPeerIndex/);
    assert.match(source, /match_offer_waiting'.*searchId/);
    assert.match(lifecycleSource, /type: 'queue_left'/);
    assert.match(source, /effectiveMatchScope|country_fallback_available/);
});
