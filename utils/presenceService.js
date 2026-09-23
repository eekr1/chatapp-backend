const crypto = require('crypto');

const hashDevice = (value) => crypto.createHash('sha256').update(String(value || 'unknown')).digest('hex');

const createPresenceService = ({ pool, config, now = () => new Date() }) => {
    const open = async ({ connectionId, userId, sessionId, deviceId, generation = 1 }) => {
        const result = await pool.query(`
            WITH prior AS (
                SELECT EXISTS (
                    SELECT 1 FROM connection_leases WHERE user_id = $2 AND expires_at > NOW()
                ) AS was_online
            ), upserted AS (
            INSERT INTO connection_leases (
                connection_id, user_id, session_hash, device_hash, instance_id,
                generation, connected_at, last_heartbeat_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW() + ($7 * INTERVAL '1 millisecond'))
            ON CONFLICT (connection_id) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                session_hash = EXCLUDED.session_hash,
                device_hash = EXCLUDED.device_hash,
                instance_id = EXCLUDED.instance_id,
                generation = EXCLUDED.generation,
                last_heartbeat_at = NOW(),
                expires_at = EXCLUDED.expires_at
            RETURNING 1
            )
            SELECT NOT prior.was_online AS became_online FROM prior, upserted
        `, [connectionId, userId, sessionId, hashDevice(deviceId), config.instanceId, generation, config.presenceLeaseMs]);
        return { state: 'online', becameOnline: Boolean(result.rows?.[0]?.became_online), observedAt: now().toISOString() };
    };

    const heartbeat = async (connectionId) => {
        const result = await pool.query(`
            UPDATE connection_leases
            SET last_heartbeat_at = NOW(), expires_at = NOW() + ($2 * INTERVAL '1 millisecond')
            WHERE connection_id = $1 AND expires_at > NOW() - INTERVAL '5 minutes'
            RETURNING user_id
        `, [connectionId, config.presenceLeaseMs]);
        return result.rows?.[0]?.user_id || null;
    };

    const detach = async (connectionId) => {
        await pool.query(`
            UPDATE connection_leases
            SET expires_at = LEAST(expires_at, NOW() + ($2 * INTERVAL '1 millisecond'))
            WHERE connection_id = $1
        `, [connectionId, config.recoveryGraceMs]);
    };

    const closeFinal = async (connectionId) => {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const removed = await client.query('DELETE FROM connection_leases WHERE connection_id = $1 RETURNING user_id, last_heartbeat_at', [connectionId]);
            const userId = removed.rows?.[0]?.user_id || null;
            const lastActivityAt = removed.rows?.[0]?.last_heartbeat_at || null;
            let lastSeenAt = null;
            if (userId) {
                await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [String(userId)]);
                const remaining = await client.query('SELECT 1 FROM connection_leases WHERE user_id = $1 AND expires_at > NOW() LIMIT 1', [userId]);
                if (!remaining.rows.length) {
                    const updated = await client.query('UPDATE users SET last_seen_at = COALESCE($2, NOW()) WHERE id = $1 RETURNING last_seen_at', [userId, lastActivityAt]);
                    lastSeenAt = updated.rows?.[0]?.last_seen_at || null;
                }
            }
            await client.query('COMMIT');
            return { userId, becameOffline: Boolean(userId && lastSeenAt), lastSeenAt };
        } catch (error) {
            try { await client.query('ROLLBACK'); } catch { /* best effort */ }
            throw error;
        } finally {
            client.release();
        }
    };

    const cleanupExpired = async () => {
        const result = await pool.query(`
            WITH expired AS (
                DELETE FROM connection_leases WHERE expires_at <= NOW() RETURNING user_id, last_heartbeat_at
            ), affected AS (
                SELECT user_id, MAX(last_heartbeat_at) AS last_activity_at FROM expired GROUP BY user_id
            )
            UPDATE users u
            SET last_seen_at = GREATEST(COALESCE(u.last_seen_at, a.last_activity_at), a.last_activity_at)
            FROM affected a
            WHERE u.id = a.user_id
              AND NOT EXISTS (
                  SELECT 1 FROM connection_leases live
                  WHERE live.user_id = a.user_id AND live.expires_at > NOW()
              )
            RETURNING u.id, u.last_seen_at
        `);
        return result.rows.map((row) => ({ userId: row.id, lastSeenAt: row.last_seen_at }));
    };

    return { open, heartbeat, detach, closeFinal, cleanupExpired };
};

module.exports = { createPresenceService, hashDevice };
