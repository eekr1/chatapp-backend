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

router.get('/stats', async (req, res) => {
    try {
        const users = await pool.query('SELECT COUNT(*) FROM users_anon');
        const bans = await pool.query('SELECT COUNT(*) FROM bans');
        const reports = await pool.query('SELECT COUNT(*) FROM reports WHERE created_at > NOW() - INTERVAL \'24 hours\'');

        res.json({
            totalUsers: users.rows[0].count,
            totalBans: bans.rows[0].count,
            reports24h: reports.rows[0].count
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/data', async (req, res) => {
    const type = req.query.type;
    try {
        if (type === 'reports') {
            const result = await pool.query(`
                SELECT r.*, u1.device_id as reporter_device, u2.device_id as reported_device 
                FROM reports r
                LEFT JOIN users_anon u1 ON r.reporter_user_id = u1.id
                LEFT JOIN users_anon u2 ON r.reported_user_id = u2.id
                ORDER BY r.created_at DESC LIMIT 50
            `);
            res.json({ items: result.rows });
        } else {
            const result = await pool.query(`
                SELECT b.*, u.device_id 
                FROM bans b
                LEFT JOIN users_anon u ON b.user_id = u.id
                WHERE (b.ban_type = 'perm') OR (b.ban_until > NOW())
                ORDER BY b.created_at DESC
            `);
            res.json({ items: result.rows });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/ban', async (req, res) => {
    const { userId, days, reason } = req.body;
    try {
        const banType = days === 0 ? 'perm' : 'temp';
        const banUntil = days === 0 ? null : new Date(Date.now() + days * 24 * 60 * 60 * 1000);

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

module.exports = router;
