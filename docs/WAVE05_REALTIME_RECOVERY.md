# Wave 05 Realtime Recovery and Presence Contract

This runbook records the Sale Release implementation boundary. It does not authorize a production migration, Render configuration change, restart, or deploy.

## Runtime contract

- `REALTIME_RECOVERY_ENABLED`: explicit capability flag. Default is `false`; enablement in a live environment requires separate approval and staging evidence.
- `RECOVERY_GRACE_MS`: bounded to 5–60 seconds; default 15 seconds.
- `PRESENCE_HEARTBEAT_MS`: bounded to 10–60 seconds; default 30 seconds.
- `PRESENCE_LEASE_MS`: bounded to 30–180 seconds; default 90 seconds.
- `PRESENCE_STALE_MS`: bounded to 30–300 seconds; default 120 seconds.
- `INSTANCE_ID` or `RENDER_INSTANCE_ID`: non-secret instance label; bounded to 120 characters.
- `REALTIME_TOPOLOGY`: `single` or `shared-db`. The Sale Release implementation uses PostgreSQL as the presence source of truth; Redis/distributed realtime fan-out is deferred.

No recovery/session token, raw device identifier, IP address, message body, or friend graph is written to the presence registry or logs. Device identity is SHA-256 hashed and the existing session hash is used as the server-side session binding.

## Protocol order

1. Socket opens and receives legacy-compatible `hello`.
2. Client sends authenticated `hello_ack`, optionally with tab-scoped recovery token and prior server epoch.
3. Server validates auth/legal/account state and creates or rotates the recovery lease.
4. Server writes the bounded PostgreSQL connection lease.
5. Server sends `welcome`, then exactly one `recovery_snapshot` before normal protected commands or outbox flush.
6. Current-connection events carry `connectionId`, `serverEpoch`, and monotonic `stateRevision`.
7. Old connection, epoch, revision, or entity evidence is ignored by the client.

The snapshot active state is a single discriminated kind: `idle`, `queue`, `offer`, or `anonymous_room`. It never invents anonymous message history. A missing/expired/restarted state is an explicit reset and never triggers automatic requeue.

## Presence and last seen

- Only authenticated, unexpired rows in `connection_leases` count as online.
- One device closing does not make a user offline while another valid lease exists.
- Clean/detached close is finalized once; abrupt expiry uses the last trustworthy heartbeat for `users.last_seen_at`.
- `/friends/list` uses one set-based query and the indexed shared lease table; no process-local map fallback is exposed as product truth.
- Presence events are sent only to accepted friends and are filtered against blocks.
- A failed or stale source is rendered as `unknown`, never guessed as Online or Offline.

## Rollback

1. Disable `REALTIME_RECOVERY_ENABLED`; new connections receive safe fresh/idle snapshots and close cleanup returns to immediate behavior.
2. Keep migration `002` in place; it is additive and must not be destructively rolled back during an incident.
3. If presence storage is unhealthy, stop claiming Online and keep the client on the neutral unknown state.
4. Do not replay anonymous sends or automatically rejoin queues during rollback.
5. Any production flag/config change, migration, restart, or deploy requires explicit user approval and the Wave 04 deploy runbook.

## Deferred checkpoint evidence

- Two real browser profiles across queue, offer, anonymous room, grace expiry, and restart.
- Multi-device clean close and abrupt network-loss expiry.
- Render instance count, WebSocket affinity, and multi-instance fan-out topology.
- Real PostgreSQL migration/query plan and representative friend-list latency.
- Desktop, narrow viewport, screen reader, keyboard, 200% text, reduced motion, and existing Android build background/foreground QA.
