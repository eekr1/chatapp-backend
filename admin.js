const express = require('express');
const router = express.Router();
const https = require('https');
const path = require('path');
const { pool } = require('./db');
const { getPushDiagnostics } = require('./utils/push');
const {
    fetchLegalSettings,
    validateLegalContentPayload,
    saveLegalSettings
} = require('./utils/legalContent');

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
        req.adminUser = login;
        return next();
    }

    res.set('WWW-Authenticate', 'Basic realm="401"');
    res.status(401).send('Authentication required.');
};

router.use(basicAuth);
router.use('/assets', express.static(path.join(__dirname, 'public', 'admin')));

const ALLOWED_DELETION_REQUEST_STATUS = new Set(['requested', 'completed', 'rejected']);
const normalizeDeletionStatus = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    if (!normalized) return 'requested';
    return ALLOWED_DELETION_REQUEST_STATUS.has(normalized) ? normalized : null;
};
const clampHours = (value, fallback = 24) => Math.max(1, Math.min(24 * 14, Number(value) || fallback));
const clampLimit = (value, fallback = 100, max = 200) => Math.max(1, Math.min(max, Number(value) || fallback));
const clampPage = (value, fallback = 1) => Math.max(1, Math.min(100000, Number(value) || fallback));
const clampProfilePageSize = (value, fallback = 50) => Math.max(1, Math.min(100, Number(value) || fallback));
const GEO_LOOKUP_TIMEOUT_MS = Math.max(500, Math.min(5000, Number(process.env.ADMIN_GEO_LOOKUP_TIMEOUT_MS) || 1800));
const GEO_CACHE_TTL_MS = Math.max(60000, Math.min(7 * 24 * 60 * 60 * 1000, Number(process.env.ADMIN_GEO_CACHE_TTL_MS) || 24 * 60 * 60 * 1000));
const geoLookupCache = new Map();
const PROFILE_SORT_COLUMN_MAP = Object.freeze({
    created_at: 'u.created_at',
    last_seen_at: 'u.last_seen_at',
    username: 'u.username'
});
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUuid = (value) => typeof value === 'string' && UUID_RE.test(value);
const normalizeProfileSortBy = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    return PROFILE_SORT_COLUMN_MAP[normalized] ? normalized : 'created_at';
};
const normalizeProfileSortDir = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    return normalized === 'asc' ? 'asc' : 'desc';
};
const normalizeIpForDisplay = (value) => {
    const raw = String(value || '').trim();
    if (!raw) return '';
    const first = raw.split(',')[0].trim();
    if (first.startsWith('::ffff:')) return first.slice(7);
    return first;
};
const isPrivateIpv4 = (ip) => {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
    const [a, b] = ip.split('.').map((v) => Number(v));
    if ([a, b].some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    return false;
};
const isPrivateIpv6 = (ip) => {
    const normalized = String(ip || '').trim().toLowerCase();
    if (!normalized) return false;
    if (normalized === '::1') return true;
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true;
    return false;
};
const getCachedGeoLocation = (ip) => {
    const cached = geoLookupCache.get(ip);
    if (!cached) return null;
    if (cached.expiresAt <= Date.now()) {
        geoLookupCache.delete(ip);
        return null;
    }
    return cached.value;
};
const setCachedGeoLocation = (ip, value) => {
    geoLookupCache.set(ip, {
        value,
        expiresAt: Date.now() + GEO_CACHE_TTL_MS
    });
};
const requestGeoJson = (url) => new Promise((resolve, reject) => {
    const req = https.get(url, {
        headers: {
            'Accept': 'application/json',
            'User-Agent': 'TalkX-Admin/1.0'
        }
    }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
            const status = Number(res.statusCode) || 0;
            if (status < 200 || status >= 300) {
                return reject(new Error(`Geo HTTP ${status}`));
            }
            const raw = Buffer.concat(chunks).toString('utf8');
            try {
                resolve(raw ? JSON.parse(raw) : {});
            } catch (e) {
                reject(new Error(`Geo JSON parse failed: ${e.message}`));
            }
        });
    });
    req.on('error', reject);
    req.setTimeout(GEO_LOOKUP_TIMEOUT_MS, () => {
        req.destroy(new Error('Geo lookup timeout'));
    });
});
const normalizeLocationText = (value) => {
    const clean = String(value || '').trim();
    return clean || null;
};
const lookupGeoFromIpApiCo = async (ip) => {
    const json = await requestGeoJson(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
    if (json?.error) return null;
    const city = normalizeLocationText(json?.city);
    const country = normalizeLocationText(json?.country_name || json?.country);
    if (!city && !country) return null;
    return {
        city,
        country,
        source: 'ipapi.co'
    };
};
const lookupGeoFromIpWhoIs = async (ip) => {
    const json = await requestGeoJson(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (json?.success === false) return null;
    const city = normalizeLocationText(json?.city);
    const country = normalizeLocationText(json?.country);
    if (!city && !country) return null;
    return {
        city,
        country,
        source: 'ipwho.is'
    };
};
const buildFallbackLocation = (ip) => {
    if (!ip) {
        return {
            city: null,
            country: null,
            label: null,
            source: 'none'
        };
    }
    if (ip === '::1') {
        return {
            city: null,
            country: null,
            label: `Lokal cihaz (${ip})`,
            source: 'local'
        };
    }
    if (isPrivateIpv4(ip) || isPrivateIpv6(ip)) {
        return {
            city: null,
            country: null,
            label: `Ozel ag (${ip})`,
            source: 'private'
        };
    }
    return {
        city: null,
        country: null,
        label: `Sehir/ulke bulunamadi (${ip})`,
        source: 'unresolved'
    };
};
const resolveRegistrationLocation = async (ipValue) => {
    const ip = normalizeIpForDisplay(ipValue);
    const fallback = buildFallbackLocation(ip);
    if (!ip) return fallback;

    const cached = getCachedGeoLocation(ip);
    if (cached) return cached;

    if (fallback.source === 'local' || fallback.source === 'private') {
        setCachedGeoLocation(ip, fallback);
        return fallback;
    }

    let resolved = null;
    try {
        resolved = await lookupGeoFromIpApiCo(ip);
    } catch {
        resolved = null;
    }
    if (!resolved) {
        try {
            resolved = await lookupGeoFromIpWhoIs(ip);
        } catch {
            resolved = null;
        }
    }

    if (!resolved) {
        setCachedGeoLocation(ip, fallback);
        return fallback;
    }

    const label = [resolved.city, resolved.country].filter(Boolean).join(', ');
    const value = {
        city: resolved.city || null,
        country: resolved.country || null,
        label: label || fallback.label,
        source: resolved.source
    };
    setCachedGeoLocation(ip, value);
    return value;
};
const logAdminAudit = async (dbOrPool, {
    actorAdmin = 'admin',
    actionType,
    entityType,
    entityId = null,
    payload = {}
}) => {
    if (!actionType || !entityType) return;
    const db = dbOrPool || pool;
    await db.query(
        `INSERT INTO admin_action_audit
          (actor_admin, action_type, entity_type, entity_id, payload, created_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, NOW())`,
        [
            String(actorAdmin || 'admin').slice(0, 120),
            String(actionType).slice(0, 80),
            String(entityType).slice(0, 80),
            entityId ? String(entityId).slice(0, 180) : null,
            JSON.stringify(payload || {})
        ]
    );
};

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
        const supportReports = await pool.query('SELECT COUNT(*) FROM support_reports WHERE created_at > NOW() - INTERVAL \'24 hours\'');
        const active = await pool.query('SELECT COUNT(*) FROM conversations WHERE ended_at IS NULL');

        res.json({
            totalUsers: users.rows[0].count,
            totalBans: bans.rows[0].count,
            reports24h: reports.rows[0].count,
            supportReports24h: supportReports.rows[0].count,
            activeConversations: active.rows[0].count
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/legal', async (req, res) => {
    try {
        const { item, updatedAt } = await fetchLegalSettings(pool);
        res.json({ item, updatedAt });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.put('/legal', async (req, res) => {
    const validation = validateLegalContentPayload(req.body);
    if (!validation.ok) {
        return res.status(400).json({ error: validation.error });
    }

    try {
        const updatedAt = await saveLegalSettings(pool, validation.value);
        await logAdminAudit(pool, {
            actorAdmin: req.adminUser,
            actionType: 'LEGAL_UPDATE',
            entityType: 'app_settings',
            entityId: 'legal_content_v1',
            payload: {
                versions: validation.value?.versions || {},
                updatedAt
            }
        });
        res.json({ success: true, item: validation.value, updatedAt });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.get('/data', async (req, res) => {
    const type = req.query.type;
    const search = String(req.query.q || '').trim(); // Search query

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
            const sortBy = normalizeProfileSortBy(req.query.sortBy);
            const sortDir = normalizeProfileSortDir(req.query.sortDir);
            const page = clampPage(req.query.page, 1);
            const pageSize = clampProfilePageSize(req.query.pageSize, 50);
            const offset = (page - 1) * pageSize;
            const where = [];
            const params = [];

            if (search) {
                params.push(`%${search}%`);
                where.push(`(u.username ILIKE $${params.length} OR COALESCE(p.display_name, '') ILIKE $${params.length})`);
            }
            const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

            const totalRes = await pool.query(
                `
                SELECT COUNT(*)::int AS total
                FROM users u
                LEFT JOIN profiles p ON u.id = p.user_id
                ${whereSql}
                `,
                params
            );

            params.push(pageSize);
            const limitParam = params.length;
            params.push(offset);
            const offsetParam = params.length;
            const orderColumn = PROFILE_SORT_COLUMN_MAP[sortBy];

            const result = await pool.query(
                `
                SELECT u.id, u.username, u.created_at, u.last_seen_at,
                       p.display_name, p.avatar_url, p.bio
                FROM users u
                LEFT JOIN profiles p ON u.id = p.user_id
                ${whereSql}
                ORDER BY ${orderColumn} ${sortDir.toUpperCase()} NULLS LAST, u.id ASC
                LIMIT $${limitParam}
                OFFSET $${offsetParam}
                `,
                params
            );

            const total = Number(totalRes.rows[0]?.total) || 0;
            const totalPages = total > 0 ? Math.ceil(total / pageSize) : 0;

            res.json({
                items: result.rows,
                pagination: {
                    page,
                    pageSize,
                    total,
                    totalPages,
                    sortBy,
                    sortDir
                }
            });
        } else if (type === 'app_reports') {
            const params = [];
            let whereSql = '';
            if (search) {
                params.push(`%${search}%`);
                whereSql = `
                    WHERE sr.subject ILIKE $1
                       OR sr.description ILIKE $1
                       OR COALESCE(sr.contact_email, '') ILIKE $1
                       OR COALESCE(sr.username_snapshot, '') ILIKE $1
                       OR COALESCE(sr.brevo_status, '') ILIKE $1
                `;
            }
            const limitParam = params.length + 1;
            params.push(100);

            const result = await pool.query(
                `
                SELECT
                    sr.id,
                    sr.subject,
                    sr.description,
                    sr.contact_email,
                    sr.user_id,
                    sr.username_snapshot,
                    sr.app_version,
                    sr.platform,
                    sr.device_model,
                    sr.client_timestamp,
                    sr.network_type,
                    sr.last_error_code,
                    sr.brevo_status,
                    sr.created_at,
                    COUNT(srm.id)::int AS media_count
                FROM support_reports sr
                LEFT JOIN support_report_media srm ON srm.report_id = sr.id
                ${whereSql}
                GROUP BY sr.id
                ORDER BY sr.created_at DESC
                LIMIT $${limitParam}
                `,
                params
            );
            res.json({ items: result.rows });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/profile-details/:userId', async (req, res) => {
    const userId = String(req.params.userId || '').trim();
    if (!userId) return res.status(400).json({ error: 'Kullanici kimligi gerekli.' });

    try {
        const profileRes = await pool.query(
            `
            SELECT
                u.id,
                u.username,
                u.status,
                u.created_at,
                u.last_seen_at,
                p.display_name
            FROM users u
            LEFT JOIN profiles p ON p.user_id = u.id
            WHERE u.id = $1
            LIMIT 1
            `,
            [userId]
        );
        if (!profileRes.rows.length) return res.status(404).json({ error: 'Kullanici bulunamadi.' });

        const [registrationRes, firstSessionRes, recentSessionsRes, pushDevicesRes] = await Promise.all([
            pool.query(
                `
                SELECT accepted_at, ip
                FROM legal_acceptances
                WHERE user_id = $1
                ORDER BY accepted_at ASC
                LIMIT 1
                `,
                [userId]
            ),
            pool.query(
                `
                SELECT device_id, created_at, expires_at
                FROM sessions
                WHERE user_id = $1
                ORDER BY created_at ASC
                LIMIT 1
                `,
                [userId]
            ),
            pool.query(
                `
                SELECT device_id, created_at, expires_at
                FROM sessions
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT 5
                `,
                [userId]
            ),
            pool.query(
                `
                SELECT device_id, platform, is_active, created_at, updated_at, last_seen_at
                FROM push_devices
                WHERE user_id = $1
                ORDER BY COALESCE(updated_at, last_seen_at, created_at) DESC
                LIMIT 5
                `,
                [userId]
            )
        ]);

        let registration = null;
        if (registrationRes.rows[0]) {
            const normalizedIp = normalizeIpForDisplay(registrationRes.rows[0].ip) || null;
            const location = await resolveRegistrationLocation(normalizedIp);
            registration = {
                ...registrationRes.rows[0],
                ip: normalizedIp,
                location_label: location?.label || null,
                location_city: location?.city || null,
                location_country: location?.country || null,
                location_source: location?.source || null
            };
        }

        res.json({
            item: profileRes.rows[0],
            registration,
            first_session: firstSessionRes.rows[0] || null,
            recent_sessions: recentSessionsRes.rows || [],
            recent_push_devices: pushDevicesRes.rows || []
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.get('/support-report/:id', async (req, res) => {
    const reportId = req.params.id;
    try {
        const reportRes = await pool.query(
            `SELECT *
             FROM support_reports
             WHERE id = $1
             LIMIT 1`,
            [reportId]
        );
        if (!reportRes.rows.length) return res.status(404).json({ error: 'Rapor bulunamadi.' });

        const mediaRes = await pool.query(
            `SELECT id, report_id, mime_type, file_name, size_bytes, media_kind, created_at
             FROM support_report_media
             WHERE report_id = $1
             ORDER BY created_at ASC`,
            [reportId]
        );

        res.json({
            item: reportRes.rows[0],
            media: mediaRes.rows
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.get('/support-report-media/:mediaId/content', async (req, res) => {
    try {
        const mediaRes = await pool.query(
            `SELECT id, mime_type, file_name, data
             FROM support_report_media
             WHERE id = $1
             LIMIT 1`,
            [req.params.mediaId]
        );
        if (!mediaRes.rows.length) return res.status(404).send('Medya bulunamadi.');

        const media = mediaRes.rows[0];
        res.setHeader('Content-Type', media.mime_type || 'application/octet-stream');
        res.setHeader('Content-Disposition', `inline; filename="${(media.file_name || 'media.bin').replace(/"/g, '')}"`);
        res.send(media.data);
    } catch (e) {
        res.status(500).send('Medya okunamadi.');
    }
});

router.delete('/support-report/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM support_reports WHERE id = $1 RETURNING id',
            [req.params.id]
        );
        if (!result.rows.length) return res.status(404).json({ error: 'Rapor bulunamadi.' });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
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
        await logAdminAudit(pool, {
            actorAdmin: req.adminUser,
            actionType: 'BAN',
            entityType: 'user',
            entityId: userId,
            payload: {
                banType,
                banUntil,
                reason: reason || null
            }
        });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/unban', async (req, res) => {
    const { userId } = req.body;
    try {
        await pool.query('DELETE FROM bans WHERE user_id = $1', [userId]);
        await logAdminAudit(pool, {
            actorAdmin: req.adminUser,
            actionType: 'UNBAN',
            entityType: 'user',
            entityId: userId,
            payload: {}
        });
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

// Add Friend Action
router.post('/add-friend', async (req, res) => {
    const userId = String(req.body?.userId || '').trim();
    const friendRef = String(req.body?.friendRef || req.body?.friendUserId || req.body?.friendId || '').trim();

    if (!isUuid(userId)) {
        return res.status(400).json({ error: 'Gecerli hedef kullanici kimligi gerekli.' });
    }
    if (!friendRef) {
        return res.status(400).json({ error: 'Eklenecek kullanici gerekli (kullanici adi veya UUID).' });
    }

    const db = await pool.connect();
    try {
        await db.query('BEGIN');

        const ownerRes = await db.query('SELECT id FROM users WHERE id = $1 LIMIT 1', [userId]);
        if (!ownerRes.rows.length) {
            await db.query('ROLLBACK');
            return res.status(404).json({ error: 'Hedef profil bulunamadi.' });
        }

        let friendUserId = null;
        let friendUsername = null;

        if (isUuid(friendRef)) {
            const friendRes = await db.query('SELECT id, username FROM users WHERE id = $1 LIMIT 1', [friendRef]);
            if (!friendRes.rows.length) {
                await db.query('ROLLBACK');
                return res.status(404).json({ error: 'Eklenecek kullanici bulunamadi.' });
            }
            friendUserId = friendRes.rows[0].id;
            friendUsername = friendRes.rows[0].username || null;
        } else {
            const normalizedUsername = friendRef.toLowerCase();
            const friendRes = await db.query('SELECT id, username FROM users WHERE username = $1 LIMIT 1', [normalizedUsername]);
            if (!friendRes.rows.length) {
                await db.query('ROLLBACK');
                return res.status(404).json({ error: 'Bu kullanici adina sahip profil bulunamadi.' });
            }
            friendUserId = friendRes.rows[0].id;
            friendUsername = friendRes.rows[0].username || null;
        }

        if (!friendUserId || friendUserId === userId) {
            await db.query('ROLLBACK');
            return res.status(400).json({ error: 'Kullanici kendisini arkadas olarak ekleyemez.' });
        }

        const blockRes = await db.query(
            `SELECT 1 FROM blocks
             WHERE (blocker_id = $1 AND blocked_id = $2)
                OR (blocker_id = $2 AND blocked_id = $1)
             LIMIT 1`,
            [userId, friendUserId]
        );
        if (blockRes.rows.length > 0) {
            await db.query('ROLLBACK');
            return res.status(409).json({ error: 'Bu iki profil arasinda engel kaydi var. Once engeli kaldirin.' });
        }

        const existingRes = await db.query(
            `SELECT user_id, friend_user_id, status
             FROM friendships
             WHERE (user_id = $1 AND friend_user_id = $2)
                OR (user_id = $2 AND friend_user_id = $1)
             LIMIT 1`,
            [userId, friendUserId]
        );

        const existing = existingRes.rows[0] || null;
        let result = 'inserted';

        if (existing) {
            if (existing.status === 'accepted') {
                result = 'already_accepted';
            } else {
                await db.query(
                    `UPDATE friendships
                     SET status = 'accepted', updated_at = NOW()
                     WHERE (user_id = $1 AND friend_user_id = $2)
                        OR (user_id = $2 AND friend_user_id = $1)`,
                    [userId, friendUserId]
                );
                result = 'upgraded_pending';
            }
        } else {
            await db.query(
                `INSERT INTO friendships (user_id, friend_user_id, status, created_at, updated_at)
                 VALUES ($1, $2, 'accepted', NOW(), NOW())`,
                [userId, friendUserId]
            );
        }

        await logAdminAudit(db, {
            actorAdmin: req.adminUser,
            actionType: 'FRIEND_ADD',
            entityType: 'friendship',
            entityId: `${userId}:${friendUserId}`,
            payload: {
                userId,
                friendUserId,
                friendUsername,
                input: friendRef,
                result
            }
        });

        await db.query('COMMIT');

        if (req.notifyUser) {
            req.notifyUser(userId, { type: 'friend_refresh' });
            req.notifyUser(friendUserId, { type: 'friend_refresh' });
        }

        return res.json({
            success: true,
            code: result === 'already_accepted' ? 'ALREADY_FRIENDS' : 'FRIEND_ADDED',
            result,
            friendUserId,
            friendUsername
        });
    } catch (e) {
        try {
            await db.query('ROLLBACK');
        } catch {
            // Ignore rollback errors.
        }
        return res.status(500).json({ error: e.message });
    } finally {
        db.release();
    }
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

router.get('/performance/overview', async (req, res) => {
    const hours = clampHours(req.query.hours, 24);
    try {
        const totalsRes = await pool.query(
            `SELECT
                COALESCE(SUM(req_count), 0)::bigint AS total_requests,
                COALESCE(SUM(error_count), 0)::bigint AS error_requests,
                COALESCE(SUM(total_duration_ms), 0)::bigint AS total_duration_ms,
                COALESCE(SUM(slow_count), 0)::bigint AS slow_requests
             FROM http_request_metrics_minute
             WHERE bucket_minute > NOW() - ($1::text || ' hours')::interval`,
            [hours]
        );

        const percentilesRes = await pool.query(
            `SELECT
                COALESCE(ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_ms)::numeric, 1), 0)::float8 AS p50_ms,
                COALESCE(ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)::numeric, 1), 0)::float8 AS p95_ms,
                COALESCE(ROUND(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration_ms)::numeric, 1), 0)::float8 AS p99_ms
             FROM http_request_events
             WHERE created_at > NOW() - ($1::text || ' hours')::interval`,
            [hours]
        );

        const topSlowRoutesRes = await pool.query(
            `SELECT
                method,
                route,
                COUNT(*)::int AS sample_count,
                COALESCE(ROUND(AVG(duration_ms)::numeric, 1), 0)::float8 AS avg_ms,
                COALESCE(ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)::numeric, 1), 0)::float8 AS p95_ms,
                COALESCE(MAX(duration_ms), 0)::int AS max_ms
             FROM http_request_events
             WHERE created_at > NOW() - ($1::text || ' hours')::interval
             GROUP BY method, route
             HAVING COUNT(*) >= 3
             ORDER BY p95_ms DESC, avg_ms DESC
             LIMIT 10`,
            [hours]
        );

        const topErrorRoutesRes = await pool.query(
            `SELECT
                method,
                route,
                COALESCE(SUM(req_count), 0)::int AS req_count,
                COALESCE(SUM(error_count), 0)::int AS error_count,
                CASE
                    WHEN COALESCE(SUM(req_count), 0) > 0
                    THEN ROUND((COALESCE(SUM(error_count), 0)::numeric * 100.0) / COALESCE(SUM(req_count), 0), 2)
                    ELSE 0
                END::float8 AS error_rate
             FROM http_request_metrics_minute
             WHERE bucket_minute > NOW() - ($1::text || ' hours')::interval
             GROUP BY method, route
             HAVING COALESCE(SUM(error_count), 0) > 0
             ORDER BY error_count DESC, error_rate DESC
             LIMIT 10`,
            [hours]
        );

        const totals = totalsRes.rows[0] || {};
        const percentiles = percentilesRes.rows[0] || {};
        const totalRequests = Number(totals.total_requests) || 0;
        const errorRequests = Number(totals.error_requests) || 0;
        const errorRate = totalRequests > 0
            ? Math.round((errorRequests * 10000) / totalRequests) / 100
            : 0;

        return res.json({
            hours,
            total_requests: totalRequests,
            error_requests: errorRequests,
            error_rate: errorRate,
            slow_requests: Number(totals.slow_requests) || 0,
            avg_ms: totalRequests > 0
                ? Math.round(((Number(totals.total_duration_ms) || 0) / totalRequests) * 10) / 10
                : 0,
            p50_ms: Number(percentiles.p50_ms) || 0,
            p95_ms: Number(percentiles.p95_ms) || 0,
            p99_ms: Number(percentiles.p99_ms) || 0,
            top_slow_routes: topSlowRoutesRes.rows || [],
            top_error_routes: topErrorRoutesRes.rows || []
        });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

router.get('/performance/timeseries', async (req, res) => {
    const hours = clampHours(req.query.hours, 24);
    try {
        const countRes = await pool.query(
            `SELECT
                bucket_minute AS bucket,
                COALESCE(SUM(req_count), 0)::int AS req_count,
                COALESCE(SUM(error_count), 0)::int AS error_count
             FROM http_request_metrics_minute
             WHERE bucket_minute > NOW() - ($1::text || ' hours')::interval
             GROUP BY bucket_minute
             ORDER BY bucket_minute ASC`,
            [hours]
        );

        const p95Res = await pool.query(
            `SELECT
                date_trunc('minute', created_at) AS bucket,
                COALESCE(ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)::numeric, 1), 0)::float8 AS p95_ms
             FROM http_request_events
             WHERE created_at > NOW() - ($1::text || ' hours')::interval
             GROUP BY date_trunc('minute', created_at)
             ORDER BY date_trunc('minute', created_at) ASC`,
            [hours]
        );

        const p95ByBucket = new Map();
        for (const row of p95Res.rows || []) {
            const key = row.bucket instanceof Date ? row.bucket.toISOString() : String(row.bucket || '');
            p95ByBucket.set(key, Number(row.p95_ms) || 0);
        }

        const series = (countRes.rows || []).map((row) => {
            const key = row.bucket instanceof Date ? row.bucket.toISOString() : String(row.bucket || '');
            return {
                bucket: key,
                req_count: Number(row.req_count) || 0,
                error_count: Number(row.error_count) || 0,
                p95_ms: p95ByBucket.get(key) || 0
            };
        });

        return res.json({ hours, series });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

router.get('/performance/slow-requests', async (req, res) => {
    const hours = clampHours(req.query.hours, 24);
    const limit = clampLimit(req.query.limit, 100, 200);
    const minDurationMs = Math.max(250, Math.min(60000, Number(req.query.minDurationMs) || 1500));
    try {
        const result = await pool.query(
            `SELECT
                method,
                route,
                status,
                duration_ms,
                response_size_bytes,
                request_id,
                sample_reason,
                created_at
             FROM http_request_events
             WHERE created_at > NOW() - ($1::text || ' hours')::interval
               AND duration_ms >= $2
             ORDER BY duration_ms DESC, created_at DESC
             LIMIT $3`,
            [hours, minDurationMs, limit]
        );
        return res.json({
            hours,
            minDurationMs,
            items: result.rows || []
        });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

router.get('/deletion-requests', async (req, res) => {
    const status = normalizeDeletionStatus(req.query.status);
    if (!status) {
        return res.status(400).json({ error: 'Gecersiz status. requested|completed|rejected beklenir.' });
    }

    try {
        const result = await pool.query(
            `SELECT
                r.id,
                r.user_id,
                r.username_snapshot,
                r.status,
                r.requested_at,
                r.reviewed_at,
                r.reviewed_by,
                r.note,
                u.username AS current_username,
                u.status AS user_status,
                p.display_name
             FROM account_deletion_requests r
             LEFT JOIN users u ON u.id = r.user_id
             LEFT JOIN profiles p ON p.user_id = r.user_id
             WHERE r.status = $1
             ORDER BY r.requested_at DESC
             LIMIT 250`,
            [status]
        );
        return res.json({ items: result.rows });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

router.get('/deletion-requests/metrics', async (req, res) => {
    try {
        const pendingRes = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE status = 'requested')::int AS pending_count,
                COUNT(*) FILTER (
                    WHERE status = 'requested'
                      AND requested_at < NOW() - INTERVAL '72 hours'
                )::int AS overdue_count
             FROM account_deletion_requests`
        );
        const resolutionRes = await pool.query(
            `SELECT
                COALESCE(
                    ROUND(
                        AVG(EXTRACT(EPOCH FROM (reviewed_at - requested_at)) / 3600.0)::numeric,
                        2
                    ),
                    0
                )::float8 AS avg_resolution_hours_30d,
                COALESCE(
                    PERCENTILE_CONT(0.5) WITHIN GROUP (
                        ORDER BY EXTRACT(EPOCH FROM (reviewed_at - requested_at)) / 3600.0
                    ),
                    0
                )::float8 AS median_resolution_hours_30d
             FROM account_deletion_requests
             WHERE status IN ('completed', 'rejected')
               AND reviewed_at IS NOT NULL
               AND reviewed_at > NOW() - INTERVAL '30 days'`
        );

        const pending = pendingRes.rows[0] || {};
        const resolution = resolutionRes.rows[0] || {};
        return res.json({
            pending_count: Number(pending.pending_count) || 0,
            overdue_count: Number(pending.overdue_count) || 0,
            avg_resolution_hours_30d: Number(resolution.avg_resolution_hours_30d) || 0,
            median_resolution_hours_30d: Number(resolution.median_resolution_hours_30d) || 0
        });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

router.get('/audit-logs', async (req, res) => {
    const actor = String(req.query.actor || '').trim();
    const action = String(req.query.action || '').trim();
    const from = String(req.query.from || '').trim();
    const to = String(req.query.to || '').trim();
    const limit = Math.max(1, Math.min(500, Number(req.query.limit) || 120));

    const where = [];
    const params = [];
    if (actor) {
        params.push(`%${actor}%`);
        where.push(`actor_admin ILIKE $${params.length}`);
    }
    if (action) {
        params.push(action.toUpperCase());
        where.push(`action_type = $${params.length}`);
    }
    if (from) {
        params.push(from);
        where.push(`created_at >= $${params.length}::timestamptz`);
    }
    if (to) {
        params.push(to);
        where.push(`created_at <= $${params.length}::timestamptz`);
    }
    params.push(limit);

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    try {
        const result = await pool.query(
            `SELECT id, actor_admin, action_type, entity_type, entity_id, payload, created_at
             FROM admin_action_audit
             ${whereSql}
             ORDER BY created_at DESC
             LIMIT $${params.length}`,
            params
        );
        return res.json({ items: result.rows });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
});

router.post('/deletion-requests/:id/approve-delete', async (req, res) => {
    const requestId = String(req.params.id || '').trim();
    const adminUser = String(req.adminUser || 'admin').slice(0, 120);
    const note = String(req.body?.note || '').trim().slice(0, 1000) || null;
    if (!requestId) return res.status(400).json({ error: 'Talep kimligi gerekli.' });

    const db = await pool.connect();
    try {
        await db.query('BEGIN');

        const requestRes = await db.query(
            `SELECT id, user_id, username_snapshot, status
             FROM account_deletion_requests
             WHERE id = $1
             FOR UPDATE`,
            [requestId]
        );
        if (!requestRes.rows.length) {
            await db.query('ROLLBACK');
            return res.status(404).json({ error: 'Silme talebi bulunamadi.' });
        }

        const deletionRequest = requestRes.rows[0];
        if (deletionRequest.status !== 'requested') {
            await db.query('ROLLBACK');
            return res.status(400).json({ error: 'Sadece requested durumundaki talepler silinebilir.' });
        }

        const userId = deletionRequest.user_id;

        await db.query('DELETE FROM friendships WHERE user_id = $1 OR friend_user_id = $1', [userId]);
        await db.query('DELETE FROM blocks WHERE blocker_id = $1 OR blocked_id = $1', [userId]);
        await db.query('DELETE FROM messages WHERE sender_id = $1', [userId]);
        await db.query('DELETE FROM conversations WHERE user_a_id = $1 OR user_b_id = $1', [userId]);
        await db.query('DELETE FROM sessions WHERE user_id = $1', [userId]);

        await db.query(
            `UPDATE account_deletion_requests
             SET status = 'completed', reviewed_at = NOW(), reviewed_by = $1, note = $2
             WHERE id = $3`,
            [adminUser, note, requestId]
        );

        await logAdminAudit(db, {
            actorAdmin: adminUser,
            actionType: 'DELETION_APPROVE',
            entityType: 'account_deletion_request',
            entityId: requestId,
            payload: {
                userId,
                note
            }
        });

        await db.query('DELETE FROM users WHERE id = $1', [userId]);

        await db.query('COMMIT');
        return res.json({ success: true });
    } catch (e) {
        try {
            await db.query('ROLLBACK');
        } catch {
            // ignore rollback errors
        }
        console.error('deletion approve failed', { requestId, adminUser, message: e?.message || e });
        return res.status(500).json({ error: 'Kalici silme tamamlanamadi.' });
    } finally {
        db.release();
    }
});

router.post('/deletion-requests/:id/reject', async (req, res) => {
    const requestId = String(req.params.id || '').trim();
    const adminUser = String(req.adminUser || 'admin').slice(0, 120);
    const note = String(req.body?.note || '').trim().slice(0, 1000) || null;
    if (!requestId) return res.status(400).json({ error: 'Talep kimligi gerekli.' });

    const db = await pool.connect();
    try {
        await db.query('BEGIN');

        const requestRes = await db.query(
            `SELECT id, user_id
             FROM account_deletion_requests
             WHERE id = $1
             FOR UPDATE`,
            [requestId]
        );
        if (!requestRes.rows.length) {
            await db.query('ROLLBACK');
            return res.status(404).json({ error: 'Silme talebi bulunamadi.' });
        }

        const userId = requestRes.rows[0].user_id;

        await db.query(
            `UPDATE account_deletion_requests
             SET status = 'rejected', reviewed_at = NOW(), reviewed_by = $1, note = $2
             WHERE id = $3`,
            [adminUser, note, requestId]
        );
        await db.query('UPDATE users SET status = \'active\' WHERE id = $1', [userId]);
        await logAdminAudit(db, {
            actorAdmin: adminUser,
            actionType: 'DELETION_REJECT',
            entityType: 'account_deletion_request',
            entityId: requestId,
            payload: {
                userId,
                note
            }
        });

        await db.query('COMMIT');
        return res.json({ success: true });
    } catch (e) {
        try {
            await db.query('ROLLBACK');
        } catch {
            // ignore rollback errors
        }
        console.error('deletion reject failed', { requestId, adminUser, message: e?.message || e });
        return res.status(500).json({ error: 'Talep reddedilemedi.' });
    } finally {
        db.release();
    }
});

router.post('/deletion-requests/:id/reactivate', async (req, res) => {
    const requestId = String(req.params.id || '').trim();
    const adminUser = String(req.adminUser || 'admin').slice(0, 120);
    const note = String(req.body?.note || '').trim().slice(0, 1000) || null;
    if (!requestId) return res.status(400).json({ error: 'Talep kimligi gerekli.' });

    const db = await pool.connect();
    try {
        await db.query('BEGIN');

        const requestRes = await db.query(
            `SELECT id, user_id
             FROM account_deletion_requests
             WHERE id = $1
             FOR UPDATE`,
            [requestId]
        );
        if (!requestRes.rows.length) {
            await db.query('ROLLBACK');
            return res.status(404).json({ error: 'Silme talebi bulunamadi.' });
        }

        const userId = requestRes.rows[0].user_id;

        await db.query('UPDATE users SET status = \'active\' WHERE id = $1', [userId]);
        await db.query(
            `UPDATE account_deletion_requests
             SET status = 'rejected', reviewed_at = NOW(), reviewed_by = $1, note = $2
             WHERE id = $3`,
            [adminUser, note, requestId]
        );
        await logAdminAudit(db, {
            actorAdmin: adminUser,
            actionType: 'DELETION_REACTIVATE',
            entityType: 'account_deletion_request',
            entityId: requestId,
            payload: {
                userId,
                note
            }
        });

        await db.query('COMMIT');
        return res.json({ success: true });
    } catch (e) {
        try {
            await db.query('ROLLBACK');
        } catch {
            // ignore rollback errors
        }
        console.error('deletion reactivate failed', { requestId, adminUser, message: e?.message || e });
        return res.status(500).json({ error: 'Kullanici yeniden aktif edilemedi.' });
    } finally {
        db.release();
    }
});

module.exports = router;
