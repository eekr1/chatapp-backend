require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { WebSocketServer, WebSocket } = require('ws');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
const { pool, ensureTables } = require('./db');
const { validateUsername } = require('./moderation');
const adminRoutes = require('./admin');
const authRoutes = require('./routes/auth');
const profileRoutes = require('./routes/profile');
const friendsRoutes = require('./routes/friends');

// Ensure DB Tables
// Ensure DB Tables
ensureTables();

// Global State (Only Transients)
// Connected clients mapping: clientId -> { ws, dbUserId, deviceId, isShadowBanned, nickname }
const activeClients = new Map();

const app = express();
const port = process.env.PORT || 3000;

// Middleware to expose online status
app.use((req, res, next) => {
    req.isUserOnline = (userId) => {
        for (const [clientId, client] of activeClients) {
            if (client.dbUserId === userId) return true;
        }
        return false;
    };
    next();
});

app.use(express.json()); // JSON body parser for admin API
app.use(cors()); // Enable CORS for ALL origins (Production should be stricter, but this is for simplicity)

// Security: Rate Limiters
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 50, // 50 requests per IP
    message: { error: 'Çok fazla deneme. Lütfen bekleyin.' }
});

const apiLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 300, // 300 requests per IP
});

app.use('/auth', authLimiter);
app.use('/api', apiLimiter);
app.use('/friends', apiLimiter);

app.use('/admin', adminRoutes);
app.use('/auth', authRoutes);
app.use('/api', profileRoutes); // Mounting profile under /api since it's logical API (e.g. /api/me)
app.use('/friends', friendsRoutes);

app.get('/health', (req, res) => {
    res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

/**
 * Global State (Only Transients)
 * DB handles presistence. Memory only for active connections.
 * 
 * V6 UPDATE: 'username' is now fetched from DB for connected users if available.
 */
let waitingQueue = []; // [{ clientId, ws, nickname, dbUserId }]
const rooms = new Map(); // roomId -> { users: [...], sockets: {...}, conversationId: uuid }
const userRoomMap = new Map(); // clientId (socket uuid) -> roomId


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

async function setDbNickname(userId, nickname) {
    try {
        await pool.query('UPDATE users_anon SET nickname = $1, nickname_set_at = NOW() WHERE id = $2', [nickname, userId]);
        return true;
    } catch (e) { console.error(e); return false; }
}

async function checkBan(userId) {
    try {
        const res = await pool.query(`
            SELECT * FROM bans 
            WHERE user_id = $1 
            AND (ban_type = 'perm' OR ban_type = 'shadow' OR ban_until > NOW())
        `, [userId]);
        return res.rows[0];
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
        const reports24h = await pool.query(`
            SELECT COUNT(DISTINCT reporter_user_id) as cnt 
            FROM reports 
            WHERE reported_user_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
        `, [reportedId]);

        if (parseInt(reports24h.rows[0].cnt) >= 3) {
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

const joinQueue = async (ws) => {
    const clientData = activeClients.get(ws.clientId);
    if (!clientData || !clientData.dbUserId) return sendError(ws, 'AUTH_ERROR', 'Kimlik doğrulanamadı.');

    // Require nickname (V6)
    if (!clientData.nickname) {
        return sendError(ws, 'NO_NICKNAME', 'Lütfen önce kullanıcı adı belirleyin.');
    }

    // Ban Check
    const ban = await checkBan(clientData.dbUserId);
    if (ban) {
        if (ban.ban_type === 'shadow') {
            sendJson(ws, { type: 'queued' });
            return;
        }
        return sendError(ws, 'BANNED', `Yasaklandınız. Sebep: ${ban.reason}`);
    }

    leaveRoom(ws.clientId);
    removeFromQueue(ws.clientId);

    const me = {
        clientId: ws.clientId,
        ws,
        nickname: clientData.nickname,
        dbUserId: clientData.dbUserId
    };

    if (waitingQueue.length > 0) {
        let peerIndex = -1;
        let peer = null;

        for (let i = 0; i < waitingQueue.length; i++) {
            const p = waitingQueue[i];
            if (p.clientId === me.clientId) continue;

            const blocked = await checkBlock(me.dbUserId, p.dbUserId);
            if (!blocked) {
                peerIndex = i;
                peer = p;
                break;
            }
        }

        if (peer && peerIndex !== -1) {
            waitingQueue.splice(peerIndex, 1);

            const roomId = uuidv4();
            const conversationId = await createConversation(me.dbUserId, peer.dbUserId);

            createRoom(roomId, conversationId, me, peer);
        } else {
            waitingQueue.push(me);
            sendJson(ws, { type: 'queued' });
        }
    } else {
        waitingQueue.push(me);
        sendJson(ws, { type: 'queued' });
    }
};

const removeFromQueue = (clientId) => {
    waitingQueue = waitingQueue.filter(item => item.clientId !== clientId);
};

const createRoom = (roomId, conversationId, userA, userB) => {
    rooms.set(roomId, {
        users: [
            { clientId: userA.clientId, nickname: userA.nickname, username: userA.username, dbUserId: userA.dbUserId },
            { clientId: userB.clientId, nickname: userB.nickname, username: userB.username, dbUserId: userB.dbUserId }
        ],
        sockets: {
            [userA.clientId]: userA.ws,
            [userB.clientId]: userB.ws
        },
        conversationId: conversationId
    });

    userRoomMap.set(userA.clientId, roomId);
    userRoomMap.set(userB.clientId, roomId);

    sendJson(userA.ws, { type: 'matched', roomId, peerNickname: userB.nickname, peerUsername: userB.username, peerId: userB.dbUserId }); // V13: add peerId
    sendJson(userB.ws, { type: 'matched', roomId, peerNickname: userA.nickname, peerUsername: userA.username, peerId: userA.dbUserId });
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
    ws.limiter = { count: 0, lastReset: Date.now() }; // Security: Rate Limiter Init
    ws.on('pong', heartbeat);

    broadcastOnlineCount();
    sendJson(ws, { type: 'hello', clientId: ws.clientId });

    ws.on('message', async (raw) => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        // Security: WebSocket Rate Limiting
        const now = Date.now();
        if (now - ws.limiter.lastReset > 1000) {
            ws.limiter.count = 0;
            ws.limiter.lastReset = now;
        }
        ws.limiter.count++;

        if (ws.limiter.count > 5) {
            if (ws.limiter.count > 10) return ws.close(); // Hard Limit
            sendJson(ws, { type: 'error', message: 'Çok hızlı mesaj atıyorsunuz! 🐢' });
            return;
        }

        if (data.type === 'hello_ack') {
            const deviceId = data.deviceId;
            let dbUser = null;
            let isAnon = false;

            if (data.token) {
                // Token Auth
                const { hashToken } = require('./utils/security');
                const tokenHash = hashToken(data.token);
                try {
                    const sessionRes = await pool.query(`
                        SELECT s.*, u.id as user_id, u.username, u.status, p.display_name
                        FROM sessions s
                        JOIN users u ON s.user_id = u.id
                        LEFT JOIN profiles p ON u.id = p.user_id
                        WHERE s.token_hash = $1 AND s.expires_at > NOW()
                     `, [tokenHash]);

                    if (sessionRes.rows.length > 0) {
                        const session = sessionRes.rows[0];
                        dbUser = {
                            id: session.user_id,
                            username: session.username,
                            nickname: session.display_name || session.username, // Use Display Name as nickname in chat
                            status: session.status
                        };
                    }
                } catch (e) { console.error('Token Auth Error', e); }
            }

            // Fallback to Anon (Legacy / Guest) if no token or token invalid
            if (!dbUser) {
                // For now, allow anon fallback if we supported it. 
                // But since UI enforces login, this might mean "Session Expired"
                // Let's send AUTH_ERROR if token was provided but failed.
                if (data.token) {
                    return sendError(ws, 'AUTH_ERROR', 'Oturum süresi doldu.');
                }
                // If no token was provided at all (legacy client?), use getOrCreateUser
                dbUser = await getOrCreateUser(deviceId, req.socket.remoteAddress);
                isAnon = true;
            }

            if (!dbUser) return sendError(ws, 'DB_ERROR', 'Sunucu hatası.');

            // Check Status
            if (dbUser.status && dbUser.status !== 'active') {
                return sendError(ws, 'BANNED', 'Hesabınız askıya alınmış.');
            }

            // Check Bans
            const ban = await checkBan(dbUser.id);
            if (ban && ban.ban_type !== 'shadow') {
                sendError(ws, 'BANNED', `Yasaklandınız. Bitiş: ${ban.ban_until ? new Date(ban.ban_until).toLocaleString() : 'Süresiz'}. Sebep: ${ban.reason}`);
                ws.close();
                return;
            }

            const isShadow = ban && ban.ban_type === 'shadow';
            activeClients.set(ws.clientId, {
                ws,
                dbUserId: dbUser.id,
                deviceId: isAnon ? deviceId : 'auth_user',
                isShadowBanned: isShadow,
                nickname: dbUser.nickname // Display Name
            });

            sendJson(ws, { type: 'welcome', nickname: dbUser.nickname });
            return;
        }

        const clientData = activeClients.get(ws.clientId);
        if (!clientData && data.type !== 'hello_ack') return;

        switch (data.type) {
            case 'setNickname':
                // V6: Persistent Nickname Registration
                let uname = (data.nickname || "").trim();
                const check = validateUsername(uname);
                if (!check.valid) {
                    return sendError(ws, 'INVALID_NICKNAME', check.reason);
                }

                await setDbNickname(clientData.dbUserId, uname);
                clientData.nickname = uname; // Update memory
                sendJson(ws, { type: 'welcome', nickname: uname });
                break;

            case 'joinQueue':
                await joinQueue(ws);
                break;

            case 'message':
                const roomId = userRoomMap.get(ws.clientId);
                if (roomId && roomId === data.roomId) {
                    const room = rooms.get(roomId);
                    if (room) {
                        const peerObj = room.users.find(u => u.clientId !== ws.clientId);
                        if (peerObj && room.sockets[peerObj.clientId]) {
                            // Admin Log
                            if (adminRoutes.logToAdmin) {
                                adminRoutes.logToAdmin({
                                    type: 'msg',
                                    from: clientData.nickname || 'User',
                                    to: peerObj.nickname || 'Peer',
                                    content: data.content
                                });
                            }

                            sendJson(room.sockets[peerObj.clientId], {
                                type: 'message',
                                roomId,
                                from: 'peer',
                                text: data.text
                            });

                            // V13: Persist Message if Persistent Conversation
                            if (room.conversationId) {
                                pool.query(
                                    'INSERT INTO messages (conversation_id, sender_id, text, msg_type) VALUES ($1, $2, $3, $4)',
                                    [room.conversationId, clientData.dbUserId, data.text, 'text']
                                ).catch(e => console.error('Message persist error:', e));
                            }
                        }
                    }
                }
                break;

            case 'typing':
            case 'stop_typing':
                const tRoomId = userRoomMap.get(ws.clientId);
                if (tRoomId) {
                    const room = rooms.get(tRoomId);
                    if (room) {
                        const peerObj = room.users.find(u => u.clientId !== ws.clientId);
                        if (peerObj && room.sockets[peerObj.clientId]) {
                            sendJson(room.sockets[peerObj.clientId], {
                                type: data.type
                            });
                        }
                    }
                }
                break;

            case 'next':
                leaveRoom(ws.clientId, 'next');
                await joinQueue(ws); // Join with existing nickname
                break;

            case 'leave':
                leaveRoom(ws.clientId, 'leave');
                break;

            case 'image_send':
                if (!data.roomId || !data.imageData) return;
                const iRoomId = userRoomMap.get(ws.clientId);
                if (iRoomId !== data.roomId) return;
                const iRoom = rooms.get(iRoomId);
                if (!iRoom) return;

                const iSender = iRoom.users.find(u => u.clientId === ws.clientId);
                const iReceiver = iRoom.users.find(u => u.clientId !== ws.clientId);

                if (!iSender || !iReceiver) return;

                // Check Friendship
                let isFriend = false;
                try {
                    const fRes = await pool.query(
                        'SELECT 1 FROM friendships WHERE ((user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)) AND status=\'accepted\'',
                        [iSender.dbUserId, iReceiver.dbUserId]
                    );
                    isFriend = fRes.rows.length > 0;
                } catch (e) { }

                if (!isFriend) return sendJson(ws, { type: 'error', message: 'Sadece arkadaşlarınıza fotoğraf gönderebilirsiniz.' });

                // Store
                try {
                    const insertRes = await pool.query(
                        'INSERT INTO ephemeral_media (sender_id, receiver_id, media_data) VALUES ($1, $2, $3) RETURNING id',
                        [iSender.dbUserId, iReceiver.dbUserId, data.imageData]
                    );
                    const mediaId = insertRes.rows[0].id;

                    // Notify Receiver
                    if (iRoom.sockets[iReceiver.clientId]) {
                        sendJson(iRoom.sockets[iReceiver.clientId], {
                            type: 'message',
                            roomId: iRoomId,
                            senderNickname: iSender.nickname, // Standardize with normal message
                            from: 'peer',
                            msgType: 'image',
                            mediaId: mediaId,
                            text: '📸 Fotoğraf' // Placeholder text
                        });
                        // Admin Log
                        if (adminRoutes.logToAdmin) {
                            adminRoutes.logToAdmin({
                                type: 'msg',
                                from: iSender.nickname || 'User',
                                to: iReceiver.nickname || 'Peer',
                                content: '[PHOTO SENT]'
                            });
                        }
                    }
                    // Notify Sender (Echo)
                    sendJson(ws, {
                        type: 'message', // Echo as message to show in own chat? 
                        // Actually App.jsx handles generic message send confirmation differently
                        // But for image we need to show bubble too.
                        // Let's send a custom ack or handle locally?
                        // Handle locally in frontend (optimistic) or wait for confirmation.
                        // Let's send 'image_sent'
                        type: 'image_sent',
                        mediaId
                    });
                } catch (e) { console.error(e); }
                break;

            case 'fetch_image':
                if (!data.mediaId) return;
                const clientDataFetch = activeClients.get(ws.clientId);
                if (!clientDataFetch || !clientDataFetch.dbUserId) return;

                try {
                    const res = await pool.query(
                        'SELECT * FROM ephemeral_media WHERE id = $1 AND receiver_id = $2',
                        [data.mediaId, clientDataFetch.dbUserId]
                    );

                    if (res.rows.length === 0) {
                        return sendJson(ws, { type: 'image_error', mediaId: data.mediaId, message: 'Bu fotoğraf silinmiş veya süresi dolmuş.' });
                    }

                    const item = res.rows[0];
                    sendJson(ws, { type: 'image_data', mediaId: data.mediaId, imageData: item.media_data });

                    // DELETE immediately
                    await pool.query('DELETE FROM ephemeral_media WHERE id = $1', [data.mediaId]);
                } catch (e) { console.error(e); }
                break;

            case 'report':
                if (data.roomId && data.reason) {
                    handleReport(ws.clientId, data.roomId, data.reason);
                }
                break;

            case 'joinDirect':
                if (data.targetUsername) {
                    const targetUname = data.targetUsername.toLowerCase().trim();
                    const meId = clientData.dbUserId;

                    // 1. Find Target User ID
                    let targetUser = null;
                    try {
                        const tRes = await pool.query('SELECT id FROM users WHERE username = $1', [targetUname]);
                        targetUser = tRes.rows[0];
                    } catch (e) { console.error(e); }

                    if (!targetUser) return sendError(ws, 'NOT_FOUND', 'Kullanıcı bulunamadı.');

                    // 2. Check Friendship
                    let isFriend = false;
                    try {
                        const fRes = await pool.query(
                            'SELECT 1 FROM friendships WHERE ((user_id=$1 AND friend_user_id=$2) OR (user_id=$2 AND friend_user_id=$1)) AND status=\'accepted\'',
                            [meId, targetUser.id]
                        );
                        isFriend = fRes.rows.length > 0;
                    } catch (e) { console.error(e); }

                    if (!isFriend) return sendError(ws, 'NOT_FRIEND', 'Bu kullanıcı arkadaşınız değil.');

                    // 3. Check if Target is Online
                    let targetClient = null;
                    // Need to scan activeClients for this user id
                    // Optimized: We could maintain a map dbUserId -> clientId, but loop is fine for <10k users.
                    for (const [cid, cData] of activeClients) {
                        if (cData.dbUserId === targetUser.id) {
                            targetClient = cData;
                            break;
                        }
                    }

                    if (!targetClient) return sendError(ws, 'OFFLINE', 'Kullanıcı şu an çevrimdışı.');

                    // 4. Create Room Directly
                    leaveRoom(ws.clientId, 'join_direct'); // Leave current room if any
                    leaveRoom(targetClient.ws.clientId, 'join_direct'); // Target leaves their room? 
                    // Verify: Should we force pull the target out of a conversation? 
                    // Only if they are idle? Or queued? 
                    // Ideally, we prompt them. But "Direct Chat" usually implies "Call".
                    // Let's force it for V1 speed or check if they are busy.
                    // If they are in a room, maybe just error "User is busy".
                    if (userRoomMap.has(targetClient.ws.clientId)) {
                        return sendError(ws, 'BUSY', 'Kullanıcı şu an başka bir sohbetre.');
                    }

                    // Proceed
                    const roomId = uuidv4();
                    const conversationId = await createConversation(meId, targetUser.id);

                    createRoom(roomId, conversationId,
                        { ...clientData, clientId: ws.clientId }, // helper object
                        { ...targetClient, clientId: targetClient.ws.clientId }
                    );
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

    const reporterId = reporterObj.dbUserId;
    const reportedId = reportedObj.dbUserId;

    if (!reporterId || !reportedId) return;

    // 1. Unique Reporter Check (24h)
    try {
        const existing = await pool.query(
            "SELECT 1 FROM reports WHERE reporter_user_id=$1 AND reported_user_id=$2 AND created_at > NOW() - INTERVAL '24 hours'",
            [reporterId, reportedId]
        );
        if (existing.rows.length > 0) return; // Already reported
    } catch (e) {
        console.error("Report check error", e);
        return;
    }

    // 2. Calculate Weight
    let weight = 1.0;
    try {
        const rUser = await pool.query('SELECT created_at FROM users WHERE id=$1', [reporterId]);
        if (rUser.rows[0]) {
            const ageHours = (Date.now() - new Date(rUser.rows[0].created_at).getTime()) / 3600000;
            if (ageHours < 24) weight = 0.5;
        }
    } catch (e) { }

    const reasonLower = (reason || '').toLowerCase();
    if (['threat', 'hate', 'sexual', 'harassment'].some(r => reasonLower.includes(r))) weight = 1.5;
    else if (reasonLower.includes('spam') || reasonLower.includes('scam')) weight = 1.0;
    else weight = 0.75;

    // 3. Log Report
    try {
        await pool.query(
            'INSERT INTO reports (reporter_user_id, reported_user_id, conversation_id, reason, meta) VALUES ($1, $2, $3, $4, $5)',
            [reporterId, reportedId, conversationId, reason, JSON.stringify({ weight })]
        );
    } catch (e) { console.error(e); }

    // 4. Threshold & Ban Logic
    try {
        // Check 24h Score
        const res24h = await pool.query(`
            SELECT SUM((meta->>'weight')::float) as score, COUNT(DISTINCT reporter_user_id) as reporters
            FROM reports WHERE reported_user_id=$1 AND created_at > NOW() - INTERVAL '24 hours'
        `, [reportedId]);

        const score24h = parseFloat(res24h.rows[0].score || 0);
        const reporters24h = parseInt(res24h.rows[0].reporters || 0);

        if (reporters24h < 2) return; // Minimum 2 unique reporters

        let banHours = 0;

        // Base Scoring
        if (score24h >= 3.0) banHours = 1;
        else if (score24h >= 2.0) banHours = 0.5; // 30 mins

        // Check 7d (Threshold 5)
        if (banHours < 24) {
            const res7d = await pool.query(`SELECT SUM((meta->>'weight')::float) as s FROM reports WHERE reported_user_id=$1 AND created_at > NOW() - INTERVAL '7 days'`, [reportedId]);
            if ((res7d.rows[0].s || 0) >= 5.0) banHours = 24;
        }

        // Check 30d (Threshold 8)
        if (banHours < 168) {
            const res30d = await pool.query(`SELECT SUM((meta->>'weight')::float) as s FROM reports WHERE reported_user_id=$1 AND created_at > NOW() - INTERVAL '30 days'`, [reportedId]);
            if ((res30d.rows[0].s || 0) >= 8.0) banHours = 168; // 7 days
        }

        if (banHours > 0) {
            // 5. Repeat Offender Multiplier
            const history = await pool.query("SELECT COUNT(*) as c FROM bans WHERE user_id=$1 AND created_at > NOW() - INTERVAL '30 days'", [reportedId]);
            const pastBans = parseInt(history.rows[0].c || 0);

            if (pastBans > 0) {
                if (pastBans === 1) banHours = Math.max(banHours, 6);
                else if (pastBans === 2) banHours = Math.max(banHours, 24);
                else if (pastBans === 3) banHours = Math.max(banHours, 168);
                else if (pastBans >= 4) banHours = 87600; // ~10 years (Perma)
            }

            // Apply Ban
            const banUntil = new Date(Date.now() + banHours * 3600000);
            await pool.query(
                'INSERT INTO bans (user_id, ban_type, ban_until, reason, created_by) VALUES ($1, $2, $3, $4, $5)',
                [reportedId, 'system', banUntil, `Auto-Ban: Score ${score24h.toFixed(1)}, History ${pastBans}`, 'auto']
            );

            // Kick User
            const clientData = activeClients.get(reportedObj.clientId);
            if (clientData && clientData.ws) {
                sendJson(clientData.ws, { type: 'ended', reason: 'banned', message: `Hesabınız geçici olarak askıya alındı. Süre: ${banHours} saat.` });
                clientData.ws.close();
            }
        }
    } catch (e) {
        console.error("Auto-ban error", e);
    }
};

const handleBlock = async (blockerClientId, roomId) => {
    let users = null;
    let roomActive = false;
    const room = rooms.get(roomId); // Only check active room for termination
    if (room) {
        users = room.users;
        roomActive = true;
    } else {
        // Fallback for logging block even if room is gone (from recent)
        const recent = recentRooms.get(roomId);
        if (recent) users = recent.users;
    }

    if (!users) return;

    const blockerObj = users.find(u => u.clientId === blockerClientId);
    const blockedObj = users.find(u => u.clientId !== blockerClientId);

    if (!blockerObj || !blockedObj) return;

    await blockUser(blockerObj.dbUserId, blockedObj.dbUserId);
    console.log(`BLOCK: ${blockerObj.dbUserId} blocked ${blockedObj.dbUserId}`);

    // Terminate chat if active (V6 Fix)
    if (roomActive) {
        leaveRoom(blockerClientId, 'blocked');
    }
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

// Serve Frontend Static Files (Production)
app.use(express.static(path.join(__dirname, '../chatapp-frontend/dist')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../chatapp-frontend/dist/index.html'));
});

server.listen(port, () => {
    console.log(`Backend running on ${port}`);
});
