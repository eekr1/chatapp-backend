const express = require('express');
const { WebSocketServer, WebSocket } = require('ws');
const http = require('http');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;

// Health check
app.get('/health', (req, res) => {
    res.json({ ok: true });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

/**
 * Global State
 * Not: In-memory olduğu için restart ile sıfırlanır.
 */
let waitingQueue = []; // [{ clientId, ws }]
const rooms = new Map(); // roomId -> { users: [clientId, clientId], sockets: { [clientId]: ws } }
const userRoomMap = new Map(); // clientId -> roomId
const abuseRegistry = new Map(); // clientId -> { reports: number, bannedUntil: number }
const rateLimitMap = new Map(); // clientId -> { count: number, lastReset: number }

// Config
const RATE_LIMIT_WINDOW = 1000; // 1 saniye
const RATE_LIMIT_MAX = 3;
const BAN_THRESHOLD = 5;
const BAN_DURATION = 24 * 60 * 60 * 1000; // 24 saat

// Helper: Send JSON safely
const sendJson = (ws, data) => {
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(data));
    }
};

// Helper: Error event
const sendError = (ws, code, message) => {
    sendJson(ws, { type: 'error', code, message });
};

// Helper: Check Ban
const isBanned = (clientId) => {
    const record = abuseRegistry.get(clientId);
    if (!record) return false;
    if (record.bannedUntil && Date.now() < record.bannedUntil) return true;
    return false;
};

// Helper: Rate Limit
const checkRateLimit = (clientId) => {
    const now = Date.now();
    let record = rateLimitMap.get(clientId);

    if (!record || now - record.lastReset > RATE_LIMIT_WINDOW) {
        record = { count: 0, lastReset: now };
    }

    record.count++;
    rateLimitMap.set(clientId, record);

    return record.count <= RATE_LIMIT_MAX;
};

// Matchmaking Logic
const joinQueue = (ws, clientId) => {
    // Eğer zaten odadaysa önce odadan çıkaralım (temiz başlangıç)
    leaveRoom(clientId);
    removeFromQueue(clientId);

    if (isBanned(clientId)) {
        return sendError(ws, 'BANNED', 'Yasaklandınız.');
    }

    // Eşleşecek kimse var mı?
    if (waitingQueue.length > 0) {
        const peer = waitingQueue.shift();

        // Kendisiyle eşleşmesin (nadir durum ama olası)
        if (peer.clientId === clientId) {
            waitingQueue.push({ clientId, ws });
            sendJson(ws, { type: 'queued' });
            return;
        }

        const roomId = uuidv4();
        createRoom(roomId, { clientId, ws }, peer);
    } else {
        waitingQueue.push({ clientId, ws });
        sendJson(ws, { type: 'queued' });
    }
};

const removeFromQueue = (clientId) => {
    waitingQueue = waitingQueue.filter(item => item.clientId !== clientId);
};

const createRoom = (roomId, userA, userB) => {
    // Room oluştur
    rooms.set(roomId, {
        users: [userA.clientId, userB.clientId],
        sockets: {
            [userA.clientId]: userA.ws,
            [userB.clientId]: userB.ws
        }
    });

    // Mapping güncelle
    userRoomMap.set(userA.clientId, roomId);
    userRoomMap.set(userB.clientId, roomId);

    // İki tarafa da matched gönder
    sendJson(userA.ws, { type: 'matched', roomId });
    sendJson(userB.ws, { type: 'matched', roomId });
};

const leaveRoom = (clientId, reason = 'leave') => {
    const roomId = userRoomMap.get(clientId);
    if (!roomId) return;

    const room = rooms.get(roomId);
    if (room) {
        // Odadaki diğer kişiyi bul
        const peerId = room.users.find(id => id !== clientId);
        const peerWs = room.sockets[peerId];

        // İki tarafa da bittiğini söyle
        [clientId, peerId].forEach(id => {
            const ws = room.sockets[id];
            if (ws) sendJson(ws, { type: 'ended', roomId, reason: id === clientId ? reason : 'peer_left' });
            userRoomMap.delete(id);
        });

        rooms.delete(roomId);
    } else {
        userRoomMap.delete(clientId);
    }
};

// WebSocket implementation
wss.on('connection', (ws) => {
    let initialClientId = null;

    ws.on('message', (raw) => {
        let data;
        try {
            data = JSON.parse(raw);
        } catch (e) {
            return sendError(ws, 'INVALID_JSON', 'Geçersiz veri.');
        }

        // İlk mesajda clientId'yi al veya güven (gerçek pratik uygulamalarda handshake yapılmalı)
        // Burada basitleştiriyoruz, her mesajda clientId göndermesi beklenmez aslında, joinQueue'da alırız
        // Ancak bağlantı bazlı clientId takibi için ws closure kullanıyoruz.

        if (data.type === 'joinQueue') {
            if (!data.clientId) return sendError(ws, 'MISSING_CLIENT_ID', 'clientId gerekli.');
            initialClientId = data.clientId;
            joinQueue(ws, initialClientId);
            return;
        }

        // Diğer tüm eventler için clientId bilmeliyiz
        if (!initialClientId) {
            return sendError(ws, 'NOT_AUTHENTICATED', 'Önce queue\'ya katılmalısınız.');
        }

        if (!checkRateLimit(initialClientId)) {
            return sendError(ws, 'RATE_LIMIT', 'Çok hızlı mesaj gönderiyorsunuz.');
        }

        switch (data.type) {
            case 'message':
                const roomId = userRoomMap.get(initialClientId);
                if (!roomId || roomId !== data.roomId) {
                    return sendError(ws, 'INVALID_ROOM', 'Oda bulunamadı veya eşleşmediniz.');
                }

                const room = rooms.get(roomId);
                if (room) {
                    const peerId = room.users.find(id => id !== initialClientId);
                    if (peerId && room.sockets[peerId]) {
                        sendJson(room.sockets[peerId], {
                            type: 'message',
                            roomId,
                            from: 'peer',
                            text: data.text
                        });
                    }
                }
                break;

            case 'next':
                // Mevcut odadan ayrıl, sonra tekrar kuyruğa gir
                leaveRoom(initialClientId, 'next');
                joinQueue(ws, initialClientId);
                break;

            case 'leave':
                leaveRoom(initialClientId, 'leave');
                break;

            case 'report':
                if (data.roomId) {
                    handleReport(initialClientId, data.roomId, data.reason);
                }
                break;

            default:
                // Bilinmeyen event
                break;
        }
    });

    ws.on('close', () => {
        if (initialClientId) {
            removeFromQueue(initialClientId);
            leaveRoom(initialClientId, 'disconnect');
        }
    });

    ws.on('error', console.error);
});

const handleReport = (reporterId, roomId, reason) => {
    // Odayı bulup kimi rapor ettiğini anla
    // Oda kapanmış olabilir, loglardan veya geçmişten bulmak gerekir ama memory'de oda siliniyor leave'de.
    // Kullanıcı rapor etmeden leave yaparsa oda silinir. Rapor edip leave yapmalı. 
    // Veya oda silinse de bir süre saklanmalı. MVP için: Oda aktifken rapor edilebilir varsayalım.
    // Eğer oda kapandıysa rapor işlenemez (Basit MVP).
    const room = rooms.get(roomId);
    if (!room) return;

    const recordedPeerId = room.users.find(id => id !== reporterId);
    if (!recordedPeerId) return;

    console.log(`REPORT: ${reporterId} reported ${recordedPeerId} for ${reason}`);

    let record = abuseRegistry.get(recordedPeerId) || { reports: 0 };
    record.reports++;

    if (record.reports >= BAN_THRESHOLD) {
        record.bannedUntil = Date.now() + BAN_DURATION;
        console.log(`BAN: ${recordedPeerId} banned until ${new Date(record.bannedUntil)}`);
        // O an bağlıysa at
        const peerWs = room.sockets[recordedPeerId];
        if (peerWs) {
            sendError(peerWs, 'BANNED', 'Yasaklandınız.');
            peerWs.close();
        }
    }
    abuseRegistry.set(recordedPeerId, record);
}

server.listen(port, () => {
    console.log(`Backend ${port} portunda çalışıyor.`);
});
