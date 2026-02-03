const express = require('express');
const router = express.Router();
const path = require('path');
const { pool } = require('./db');

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

module.exports = router;
