const express = require('express');
const router = express.Router();
const path = require('path');
const { pool } = require('./db');
const { getPushDiagnostics } = require('./utils/push');

const isEnvEnabled = (value) => ['1', 'true', 'yes', 'on'].includes(String(value || '').toLowerCase());
const hasSecureAdminPassword = () => {
    const pass = process.env.ADMIN_PASSWORD;
    return !!pass && pass !== 'admin123';
};

// Disable admin panel in production unless explicitly enabled and secure password is set.
router.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        if (!isEnvEnabled(process.env.ADMIN_PANEL_ENABLED) || !hasSecureAdminPassword()) {
            return res.status(503).send('Admin panel is disabled.');
        }
    }
    next();
});

// Basic Auth Middleware
const basicAuth = (req, res, next) => {
    const auth = { login: process.env.ADMIN_USER || 'admin', password: process.env.ADMIN_PASSWORD || 'admin123' };
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');

    if (login && password && login === auth.login && password === auth.password) {
        return next();
    }

    res.set('WWW-Authenticate', 'Basic realm="401"');
    res.status(401).send('Authentication required.');
};

router.use(basicAuth);

// Admin Dashboard HTML (Serve Static File)
router.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});


// SSE Clients for Live Logs
let logClients = [];

router.logToAdmin = (data) => {
    const msg = `data: ${JSON.stringify(data)}\n\n`;
    logClients.forEach(res => res.write(msg));
};

router.get('/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    logClients.push(res);

    req.on('close', () => {
        logClients = logClients.filter(c => c !== res);
    });
});

router.get('/stats', async (req, res) => {
    try {
        const users = await pool.query('SELECT COUNT(*) FROM users');
        const bans = await pool.query('SELECT COUNT(*) FROM bans');
        const reports = await pool.query('SELECT COUNT(*) FROM reports WHERE created_at > NOW() - INTERVAL \'24 hours\'');
        const active = await pool.query('SELECT COUNT(*) FROM conversations WHERE ended_at IS NULL');

        res.json({
            totalUsers: users.rows[0].count,
            totalBans: bans.rows[0].count,
            reports24h: reports.rows[0].count,
            activeConversations: active.rows[0].count
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/data', async (req, res) => {
    const type = req.query.type;
    const search = req.query.q || ''; // Search query

    try {
        if (type === 'reports') {
            const result = await pool.query(`
                SELECT r.*, 
                       COALESCE(u1.username, 'Anon') as reporter, 
                       COALESCE(u2.username, 'Anon') as reported
                FROM reports r
                LEFT JOIN users u1 ON r.reporter_user_id = u1.id
                LEFT JOIN users u2 ON r.reported_user_id = u2.id
                ORDER BY r.created_at DESC LIMIT 50
            `);
            res.json({ items: result.rows });
        } else if (type === 'bans') {
            const result = await pool.query(`
                SELECT b.*, u.username as nickname 
                FROM bans b
                LEFT JOIN users u ON b.user_id = u.id
                WHERE (b.ban_until > NOW()) OR (b.ban_type IN ('perm', 'shadow'))
                ORDER BY b.created_at DESC
            `);
            res.json({ items: result.rows });
        } else if (type === 'profiles') {
            // V6: List profiles with Search
            let query = `
                SELECT u.id, u.username, u.created_at, u.last_seen_at,
                       p.display_name, p.avatar_url, p.bio
                FROM users u
                LEFT JOIN profiles p ON u.id = p.user_id
            `;
            const params = [];

            if (search) {
                query += ` WHERE u.username ILIKE $1 OR p.display_name ILIKE $1`;
                params.push(`%${search}%`);
            }

            query += ` ORDER BY u.last_seen_at DESC LIMIT 100`;

            const result = await pool.query(query, params);
            res.json({ items: result.rows });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get user specific blocks
router.get('/user-blocks/:userId', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT b.blocked_id, u.username as nickname 
            FROM blocks b
            LEFT JOIN users u ON b.blocked_id = u.id
            WHERE b.blocker_id = $1
        `, [req.params.userId]);
        res.json({ items: result.rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Get user friends
router.get('/user-friends/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const result = await pool.query(`
            SELECT u.id, u.username, u.created_at 
            FROM friendships f
            JOIN users u ON (f.user_id = u.id OR f.friend_user_id = u.id)
            WHERE (f.user_id = $1 OR f.friend_user_id = $1) 
              AND f.status = 'accepted'
              AND u.id != $1
        `, [userId]);
        res.json({ items: result.rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Deep Stats: Reports
router.get('/user-reports/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;

        // Received Reports
        const receivedRes = await pool.query(`
            SELECT r.*, u.username as reporter_name
            FROM reports r
            LEFT JOIN users u ON r.reporter_user_id = u.id
            WHERE r.reported_user_id = $1
            ORDER BY r.created_at DESC LIMIT 20
        `, [userId]);

        // Sent Reports
        const sentRes = await pool.query(`
            SELECT r.*, u.username as reported_name
            FROM reports r
            LEFT JOIN users u ON r.reported_user_id = u.id
            WHERE r.reporter_user_id = $1
            ORDER BY r.created_at DESC LIMIT 20
        `, [userId]);

        // Counts
        const receivedCount = await pool.query('SELECT COUNT(*) FROM reports WHERE reported_user_id=$1', [userId]);
        const sentCount = await pool.query('SELECT COUNT(*) FROM reports WHERE reporter_user_id=$1', [userId]);

        res.json({
            received: receivedRes.rows,
            sent: sentRes.rows,
            stats: {
                receivedCount: receivedCount.rows[0].count,
                sentCount: sentCount.rows[0].count
            }
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/ban', async (req, res) => {
    const { userId, days, reason, type } = req.body;
    try {
        let banType = 'temp';
        let banUntil = null;

        if (type === 'shadow') {
            banType = 'shadow';
            banUntil = null;
        } else if (days === 0) {
            banType = 'perm';
            banUntil = null;
        } else {
            banType = 'temp';
            banUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
        }

        await pool.query(
            'INSERT INTO bans (user_id, ban_type, ban_until, reason, created_by) VALUES ($1, $2, $3, $4, $5)',
            [userId, banType, banUntil, reason, 'admin']
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/unban', async (req, res) => {
    const { userId } = req.body;
    try {
        await pool.query('DELETE FROM bans WHERE user_id = $1', [userId]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Unblock Action
router.post('/unblock', async (req, res) => {
    const { blockerId, blockedId } = req.body;
    try {
        await pool.query('DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [blockerId, blockedId]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Remove Friend Action
router.post('/remove-friend', async (req, res) => {
    const { userId, friendId } = req.body;
    try {
        await pool.query(`
            DELETE FROM friendships 
            WHERE (user_id = $1 AND friend_user_id = $2) 
               OR (user_id = $2 AND friend_user_id = $1)
        `, [userId, friendId]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/notify', async (req, res) => {
    const title = (req.body.title || '').trim();
    const body = (req.body.body || '').trim();
    const durationMs = req.body.durationMs;
    const target = req.body.target || 'all';

    if (!title || !body) {
        return res.status(400).json({ error: 'title ve body gerekli.' });
    }
    if (typeof router.sendSystemNotice !== 'function') {
        return res.status(503).json({ error: 'Bildirim sistemi hazir degil.' });
    }

    try {
        const result = await router.sendSystemNotice({ title, body, durationMs, target });
        res.json({ success: true, ...result });
    } catch (e) {
        console.error('admin notify error:', e);
        res.status(500).json({ error: 'Bildirim gonderilemedi.' });
    }
});

router.get('/push/health', async (req, res) => {
    const minutes = Math.max(1, Math.min(24 * 60, Number(req.query.minutes) || 60));
    try {
        const agg = await pool.query(
            `SELECT
                COUNT(*)::int AS total_events,
                COALESCE(SUM(token_count), 0)::int AS token_count,
                COALESCE(SUM(sent_count), 0)::int AS sent_count,
                COALESCE(SUM(failure_count), 0)::int AS failure_count,
                COALESCE(SUM(invalid_token_count), 0)::int AS invalid_token_count
             FROM push_delivery_logs
             WHERE created_at > NOW() - ($1::text || ' minutes')::interval`,
            [minutes]
        );

        const byType = await pool.query(
            `SELECT event_type,
                    COUNT(*)::int AS events,
                    COALESCE(SUM(sent_count), 0)::int AS sent_count,
                    COALESCE(SUM(failure_count), 0)::int AS failure_count
             FROM push_delivery_logs
             WHERE created_at > NOW() - ($1::text || ' minutes')::interval
             GROUP BY event_type
             ORDER BY events DESC`,
            [minutes]
        );

        const row = agg.rows[0] || {};
        const totalOut = (Number(row.sent_count) || 0) + (Number(row.failure_count) || 0);
        const successRate = totalOut > 0 ? Math.round(((Number(row.sent_count) || 0) / totalOut) * 1000) / 10 : 0;
        res.json({
            minutes,
            totalEvents: Number(row.total_events) || 0,
            tokenCount: Number(row.token_count) || 0,
            sentCount: Number(row.sent_count) || 0,
            failureCount: Number(row.failure_count) || 0,
            invalidTokenCount: Number(row.invalid_token_count) || 0,
            successRate,
            byType: byType.rows || []
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.get('/push/diagnostics', async (req, res) => {
    const hours = Math.max(1, Math.min(24 * 14, Number(req.query.hours) || 24));
    try {
        const firebase = getPushDiagnostics();

        const totalsRes = await pool.query(
            `SELECT
                COALESCE(SUM(sent_count), 0)::int AS sent_count,
                COALESCE(SUM(failure_count), 0)::int AS failure_count,
                COALESCE(SUM(invalid_token_count), 0)::int AS invalid_token_count
             FROM push_delivery_logs
             WHERE created_at > NOW() - ($1::text || ' hours')::interval`,
            [hours]
        );

        const byTypeRes = await pool.query(
            `SELECT event_type,
                    COUNT(*)::int AS events,
                    COALESCE(SUM(sent_count), 0)::int AS sent_count,
                    COALESCE(SUM(failure_count), 0)::int AS failure_count,
                    COALESCE(SUM(invalid_token_count), 0)::int AS invalid_token_count
             FROM push_delivery_logs
             WHERE created_at > NOW() - ($1::text || ' hours')::interval
             GROUP BY event_type
             ORDER BY events DESC`,
            [hours]
        );

        const errorSummaryRes = await pool.query(
            `SELECT err.key AS code,
                    SUM(
                        COALESCE(
                            NULLIF(regexp_replace(err.value, '[^0-9-]', '', 'g'), '')::int,
                            0
                        )
                    )::int AS count
             FROM push_delivery_logs l
             CROSS JOIN LATERAL jsonb_each_text(COALESCE(l.meta->'errorSummary', '{}'::jsonb)) AS err(key, value)
             WHERE l.created_at > NOW() - ($1::text || ' hours')::interval
             GROUP BY err.key
             ORDER BY count DESC
             LIMIT 12`,
            [hours]
        );

        const devicesRes = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE is_active = TRUE)::int AS active_count,
                COUNT(*)::int AS total_count,
                MAX(updated_at) FILTER (WHERE is_active = TRUE) AS last_active_updated_at
             FROM push_devices`
        );

        const platformRes = await pool.query(
            `SELECT platform, COUNT(*)::int AS count
             FROM push_devices
             WHERE is_active = TRUE
             GROUP BY platform
             ORDER BY count DESC`
        );

        const freshnessRes = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE is_active = TRUE AND updated_at > NOW() - INTERVAL '5 minutes')::int AS lt_5m,
                COUNT(*) FILTER (WHERE is_active = TRUE AND updated_at > NOW() - INTERVAL '1 hour' AND updated_at <= NOW() - INTERVAL '5 minutes')::int AS lt_1h,
                COUNT(*) FILTER (WHERE is_active = TRUE AND updated_at > NOW() - INTERVAL '24 hours' AND updated_at <= NOW() - INTERVAL '1 hour')::int AS lt_24h,
                COUNT(*) FILTER (WHERE is_active = TRUE AND updated_at > NOW() - INTERVAL '7 days' AND updated_at <= NOW() - INTERVAL '24 hours')::int AS lt_7d,
                COUNT(*) FILTER (WHERE is_active = TRUE AND updated_at <= NOW() - INTERVAL '7 days')::int AS gte_7d
             FROM push_devices`
        );

        const totals = totalsRes.rows[0] || {};
        const devices = devicesRes.rows[0] || {};
        const freshness = freshnessRes.rows[0] || {};

        res.json({
            hours,
            firebase: {
                enabled: !!firebase.enabled,
                initError: firebase.initError || null,
                projectId: firebase.projectId || null,
                expectedProjectId: firebase.expectedProjectId || null,
                credentialSource: firebase.credentialSource || null,
                initializedAt: firebase.initializedAt || null
            },
            logs: {
                sentCount: Number(totals.sent_count) || 0,
                failureCount: Number(totals.failure_count) || 0,
                invalidTokenCount: Number(totals.invalid_token_count) || 0,
                byType: byTypeRes.rows || [],
                errorSummary: errorSummaryRes.rows || []
            },
            devices: {
                activeCount: Number(devices.active_count) || 0,
                totalCount: Number(devices.total_count) || 0,
                lastActiveUpdatedAt: devices.last_active_updated_at || null,
                byPlatform: platformRes.rows || [],
                freshness: {
                    lt5m: Number(freshness.lt_5m) || 0,
                    lt1h: Number(freshness.lt_1h) || 0,
                    lt24h: Number(freshness.lt_24h) || 0,
                    lt7d: Number(freshness.lt_7d) || 0,
                    gte7d: Number(freshness.gte_7d) || 0
                }
            }
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.get('/push/logs', async (req, res) => {
    const limit = Math.max(1, Math.min(200, Number(req.query.limit) || 50));
    try {
        const result = await pool.query(
            `SELECT id, delivery_id, event_type, target_user_id, token_count, sent_count, failure_count,
                    invalid_token_count, channel_id, meta, created_at
             FROM push_delivery_logs
             ORDER BY created_at DESC
             LIMIT $1`,
            [limit]
        );
        res.json({ items: result.rows });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

module.exports = router;
