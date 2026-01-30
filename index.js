const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
const { pool, ensureTables } = require('./db');
const { validateUsername } = require('./moderation');
const adminRoutes = require('./admin');

// Ensure DB Tables
ensureTables();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json()); // JSON body parser for admin API
app.use('/admin', adminRoutes);

app.get('/health', (req, res) => {
    res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

/**
 * Global State (Only Transients)
 * DB handles presistence. Memory only for active connections.
 */
let waitingQueue = []; // [{ clientId, ws, username, dbUserId }]
const rooms = new Map(); // roomId -> { users: [...], sockets: {...}, conversationId: uuid }
const userRoomMap = new Map(); // clientId (socket uuid) -> roomId

// Connected clients mapping: clientId -> { ws, dbUserId, deviceId, isShadowBanned }
const activeClients = new Map();

// Config
const RATE_LIMIT_WINDOW = 1000;
const RATE_LIMIT_MAX = 5;
const REPORT_TTL = 5 * 60 * 1000;
const HEARTBEAT_INTERVAL = 30000;

// Rate Limit Map (Memory is fine for rate limit)
const rateLimitMap = new Map();

// Recent Rooms for Report fallback (Memory cache)
const recentRooms = new Map();

// Helpers
const sendJson = (ws, data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
};

const sendError = (ws, code, message) => {
    sendJson(ws, { type: 'error', code, message });
};

const checkRateLimit = (clientId) => {
    const now = Date.now();
    let record = rateLimitMap.get(clientId);
    if (!record || now - record.lastReset > RATE_LIMIT_WINDOW) record = { count: 0, lastReset: now };
    record.count++;
    rateLimitMap.set(clientId, record);
    return record.count <= RATE_LIMIT_MAX;
};

function heartbeat() { this.isAlive = true; }

const broadcastOnlineCount = () => {
    const count = wss.clients.size;
    const msg = JSON.stringify({ type: 'onlineCount', count });
    wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
};

// --- DB Logic Helpers ---

async function getOrCreateUser(deviceId, ip) {
    try {
        let res = await pool.query('SELECT * FROM users_anon WHERE device_id = $1', [deviceId]);
        if (res.rows.length > 0) {
            // Update last seen
            await pool.query('UPDATE users_anon SET last_seen_at = NOW(), last_ip = $2 WHERE id = $1', [res.rows[0].id, ip]);
            return res.rows[0];
        } else {
            // Create
            res = await pool.query('INSERT INTO users_anon (device_id, last_ip) VALUES ($1, $2) RETURNING *', [deviceId, ip]);
            return res.rows[0];
        }
    } catch (e) {
        console.error('DB Error getOrCreateUser:', e);
        return null; // Fail safe
    }
}

async function checkBan(userId) {
    try {
        const res = await pool.query(`
            SELECT * FROM bans 
            WHERE user_id = $1 
            AND (ban_type = 'perm' OR ban_type = 'shadow' OR ban_until > NOW())
        `, [userId]);
        return res.rows[0]; // Returns ban record or undefined
    } catch (e) {
        console.error('DB Error checkBan:', e);
        return null;
    }
}

async function checkBlock(userAId, userBId) {
    try {
        const res = await pool.query(`
            SELECT 1 FROM blocks 
            WHERE (blocker_id = $1 AND blocked_id = $2) 
               OR (blocker_id = $2 AND blocked_id = $1)
        `, [userAId, userBId]);
        return res.rows.length > 0;
    } catch (e) {
        return false;
    }
}

async function blockUser(blockerId, blockedId) {
    if (blockerId === blockedId) return;
    try {
        await pool.query(
            'INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [blockerId, blockedId]
        );
    } catch (e) { console.error(e); }
}

async function createConversation(userAId, userBId) {
    try {
        const res = await pool.query(
            'INSERT INTO conversations (user_a_id, user_b_id) VALUES ($1, $2) RETURNING id',
            [userAId, userBId]
        );
        return res.rows[0].id;
    } catch (e) {
        console.error('DB Error createConversation:', e);
        return null;
    }
}

async function endConversation(conversationId, reason) {
    if (!conversationId) return;
    try {
        await pool.query(
            'UPDATE conversations SET ended_at = NOW(), ended_reason = $1 WHERE id = $2',
            [reason, conversationId]
        );
    } catch (e) { console.error('DB Error endConversation:', e); }
}

async function logReport(reporterId, reportedId, conversationId, reason) {
    try {
        // Prevent duplicate report
        const check = await pool.query(
            'SELECT id FROM reports WHERE reporter_user_id=$1 AND conversation_id=$2',
            [reporterId, conversationId]
        );
        if (check.rows.length > 0) return { duplicate: true };

        await pool.query(
            'INSERT INTO reports (reporter_user_id, reported_user_id, conversation_id, reason) VALUES ($1, $2, $3, $4)',
            [reporterId, reportedId, conversationId, reason]
        );

        // Auto Ban Logic
        // 1. Last 24h reports count from different reporters
        const reports24h = await pool.query(`
            SELECT COUNT(DISTINCT reporter_user_id) as cnt 
            FROM reports 
            WHERE reported_user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
        `, [reportedId]);

        if (parseInt(reports24h.rows[0].cnt) >= 3) {
            // Auto Ban 24h
            await pool.query(
                'INSERT INTO bans (user_id, ban_type, ban_until, reason, created_by) VALUES ($1, $2, NOW() + INTERVAL \'24 hours\', $3, $4)',
                [reportedId, 'temp', 'Auto-Ban: Too many reports (3 unique in 24h)', 'system']
            );
            return { banned: true };
        }

        return { banned: false };

    } catch (e) {
        console.error('DB Error logReport:', e);
        return {};
    }
}


// --- Main Logic ---

const joinQueue = async (ws, username) => {
    const clientData = activeClients.get(ws.clientId);
    if (!clientData || !clientData.dbUserId) return sendError(ws, 'AUTH_ERROR', 'Kimlik doğrulanamadı.');

    // DB Ban Check (Double check before queue)
    const ban = await checkBan(clientData.dbUserId);
    if (ban) {
        // SHADOWBAN LOGIC:
        if (ban.ban_type === 'shadow') {
            // Fake queue join
            sendJson(ws, { type: 'queued' });
            return; // Never actually added to waitingQueue
        }

        return sendError(ws, 'BANNED', `Yasaklandınız. Sebep: ${ban.reason}`);
    }

    leaveRoom(ws.clientId);
    removeFromQueue(ws.clientId);

    if (waitingQueue.length > 0) {
        // Try to find a valid peer (Blocking Logic)
        let peerIndex = -1;
        let peer = null;

        // Simple linear search for non-blocked peer (usually queue is small, mostly size 0 or 1)
        for (let i = 0; i < waitingQueue.length; i++) {
            const p = waitingQueue[i];
            // Don't match self
            if (p.clientId === ws.clientId) continue;

            const blocked = await checkBlock(clientData.dbUserId, p.dbUserId);
            if (!blocked) {
                peerIndex = i;
                peer = p;
                break;
            }
        }

        if (peer && peerIndex !== -1) {
            // Remove peer from queue
            waitingQueue.splice(peerIndex, 1);

            const roomId = uuidv4();
            const conversationId = await createConversation(clientData.dbUserId, peer.dbUserId);

            createRoom(roomId, conversationId,
                { clientId: ws.clientId, ws, username, dbUserId: clientData.dbUserId },
                peer
            );
        } else {
            // No valid peer found, join queue
            waitingQueue.push({ clientId: ws.clientId, ws, username, dbUserId: clientData.dbUserId });
            sendJson(ws, { type: 'queued' });
        }
    } else {
        waitingQueue.push({ clientId: ws.clientId, ws, username, dbUserId: clientData.dbUserId });
        sendJson(ws, { type: 'queued' });
    }
};

const removeFromQueue = (clientId) => {
    waitingQueue = waitingQueue.filter(item => item.clientId !== clientId);
};

const createRoom = (roomId, conversationId, userA, userB) => {
    rooms.set(roomId, {
        users: [
            { clientId: userA.clientId, username: userA.username, dbUserId: userA.dbUserId },
            { clientId: userB.clientId, username: userB.username, dbUserId: userB.dbUserId }
        ],
        sockets: {
            [userA.clientId]: userA.ws,
            [userB.clientId]: userB.ws
        },
        conversationId: conversationId
    });

    userRoomMap.set(userA.clientId, roomId);
    userRoomMap.set(userB.clientId, roomId);

    sendJson(userA.ws, { type: 'matched', roomId, peerUsername: userB.username });
    sendJson(userB.ws, { type: 'matched', roomId, peerUsername: userA.username });
};

const leaveRoom = (clientId, reason = 'leave') => {
    const roomId = userRoomMap.get(clientId);
    if (!roomId) return;

    const room = rooms.get(roomId);
    if (room) {
        endConversation(room.conversationId, reason);

        recentRooms.set(roomId, {
            users: [...room.users],
            timestamp: Date.now(),
            conversationId: room.conversationId
        });

        room.users.forEach(u => {
            const id = u.clientId;
            const ws = room.sockets[id];
            if (ws) sendJson(ws, { type: 'ended', roomId, reason: id === clientId ? reason : 'peer_left' });
            userRoomMap.delete(id);
        });
        rooms.delete(roomId);
    } else {
        userRoomMap.delete(clientId);
    }
};


wss.on('connection', (ws, req) => {
    ws.clientId = uuidv4();
    ws.isAlive = true;
    ws.username = "Anonim";
    ws.on('pong', heartbeat);

    broadcastOnlineCount();

    sendJson(ws, { type: 'hello', clientId: ws.clientId });

    ws.on('message', async (raw) => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        if (!checkRateLimit(ws.clientId)) return sendError(ws, 'RATE_LIMIT', 'Hız sınırı aşıldı.');

        if (data.type === 'hello_ack') {
            const deviceId = data.deviceId;
            const ip = req.socket.remoteAddress;
            const dbUser = await getOrCreateUser(deviceId, ip);

            if (!dbUser) return sendError(ws, 'DB_ERROR', 'Sunucu hatası.');

            const ban = await checkBan(dbUser.id);
            if (ban) {
                if (ban.ban_type === 'shadow') {
                    // Allowed to connect, but marked
                    activeClients.set(ws.clientId, { ws, dbUserId: dbUser.id, deviceId, isShadowBanned: true });
                } else {
                    sendError(ws, 'BANNED', `Yasaklandınız. Bitiş: ${ban.ban_until ? new Date(ban.ban_until).toLocaleString() : 'Süresiz'}. Sebep: ${ban.reason}`);
                    ws.close();
                    return;
                }
            } else {
                activeClients.set(ws.clientId, { ws, dbUserId: dbUser.id, deviceId });
            }
            return;
        }

        const clientData = activeClients.get(ws.clientId);
        if (!clientData && data.type !== 'hello_ack') return;

        switch (data.type) {
            case 'joinQueue':
                let uname = (data.username || "Anonim").trim().substring(0, 15);

                // Moderation Check
                const check = validateUsername(uname);
                if (!check.valid) {
                    return sendError(ws, 'INVALID_USERNAME', check.reason);
                }

                ws.username = uname;
                await joinQueue(ws, uname);
                break;

            case 'message':
                const roomId = userRoomMap.get(ws.clientId);
                if (roomId && roomId === data.roomId) {
                    const room = rooms.get(roomId);
                    if (room) {
                        const peerObj = room.users.find(u => u.clientId !== ws.clientId);
                        if (peerObj && room.sockets[peerObj.clientId]) {
                            sendJson(room.sockets[peerObj.clientId], {
                                type: 'message',
                                roomId,
                                from: 'peer',
                                text: data.text
                            });
                        }
                    }
                }
                break;

            case 'next':
                leaveRoom(ws.clientId, 'next');
                await joinQueue(ws, ws.username);
                break;

            case 'leave':
                leaveRoom(ws.clientId, 'leave');
                break;

            case 'report':
                if (data.roomId && data.reason) {
                    handleReport(ws.clientId, data.roomId, data.reason);
                }
                break;

            case 'block':
                // Personal Block Request (V5)
                if (data.roomId) {
                    handleBlock(ws.clientId, data.roomId);
                }
                break;
        }
    });

    ws.on('close', () => {
        if (activeClients.has(ws.clientId)) activeClients.delete(ws.clientId);
        removeFromQueue(ws.clientId);
        leaveRoom(ws.clientId, 'disconnect');
        broadcastOnlineCount();
    });
});

const handleReport = async (reporterClientId, roomId, reason) => {
    // ... Logic same as before
    let users = null;
    let conversationId = null;
    const room = rooms.get(roomId);
    if (room) {
        users = room.users;
        conversationId = room.conversationId;
    } else {
        const recent = recentRooms.get(roomId);
        if (recent) {
            users = recent.users;
            conversationId = recent.conversationId;
        }
    }

    if (!users || !conversationId) return;

    const reporterObj = users.find(u => u.clientId === reporterClientId);
    const reportedObj = users.find(u => u.clientId !== reporterClientId);

    if (!reporterObj || !reportedObj) return;

    // Log Report
    const result = await logReport(reporterObj.dbUserId, reportedObj.dbUserId, conversationId, reason);

    if (result.banned) {
        const clientData = activeClients.get(reportedObj.clientId);
        if (clientData && clientData.ws && clientData.ws.readyState === WebSocket.OPEN) {
            sendError(clientData.ws, 'BANNED', 'Yasaklandınız. (Auto-Ban)');
            clientData.ws.close();
        }
    }

    // Auto-Block on Report (Optional but good UX)
    // await blockUser(reporterObj.dbUserId, reportedObj.dbUserId);
};

const handleBlock = async (blockerClientId, roomId) => {
    let users = null;
    const room = rooms.get(roomId);
    if (room) users = room.users;
    else {
        const recent = recentRooms.get(roomId);
        if (recent) users = recent.users;
    }

    if (!users) return;

    const blockerObj = users.find(u => u.clientId === blockerClientId);
    const blockedObj = users.find(u => u.clientId !== blockerClientId);

    if (!blockerObj || !blockedObj) return;

    await blockUser(blockerObj.dbUserId, blockedObj.dbUserId);
    console.log(`BLOCK: ${blockerObj.dbUserId} blocked ${blockedObj.dbUserId}`);
};

// Intervals
const interval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, HEARTBEAT_INTERVAL);

// Cache Cleanup
setInterval(() => {
    const now = Date.now();
    for (const [roomId, data] of recentRooms) {
        if (now - data.timestamp > REPORT_TTL) recentRooms.delete(roomId);
    }
}, 60000);

server.listen(port, () => {
    console.log(`Backend running on ${port}`);
});
