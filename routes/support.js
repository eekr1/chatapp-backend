const express = require('express');
const rateLimit = require('express-rate-limit');
const { pool } = require('../db');
const { hashToken } = require('../utils/security');
const { sendSupportReportEmail } = require('../utils/brevoSupport');

const router = express.Router();

const SUBJECTS = new Set(['connection', 'message', 'photo', 'other']);
const SUBJECT_ALIASES = new Map([
    ['baglanti', 'connection'],
    ['bağlantı', 'connection'],
    ['mesaj', 'message'],
    ['foto', 'photo'],
    ['diger', 'other'],
    ['diğer', 'other']
]);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIME_RE = /^(image|video)\//i;
const MAX_DESCRIPTION = 2000;
const MAX_FILES = 3;
const MAX_FILE_BYTES = 8 * 1024 * 1024; // 8 MB
const MAX_TOTAL_FILE_BYTES = 16 * 1024 * 1024; // 16 MB
const MAX_MULTIPART_BODY_BYTES = MAX_TOTAL_FILE_BYTES + (2 * 1024 * 1024);
const DEFAULT_SUPPORT_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_SUPPORT_RATE_LIMIT_MAX = 10;

const cleanText = (value, max = 1000) => {
    if (typeof value !== 'string') return '';
    return value.trim().slice(0, max);
};

const toPositiveInt = (value, fallback) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
    return Math.round(parsed);
};

const SUPPORT_RATE_LIMIT_WINDOW_MS = toPositiveInt(
    process.env.SUPPORT_RATE_LIMIT_WINDOW_MS,
    DEFAULT_SUPPORT_RATE_LIMIT_WINDOW_MS
);
const SUPPORT_RATE_LIMIT_MAX = toPositiveInt(
    process.env.SUPPORT_RATE_LIMIT_MAX,
    DEFAULT_SUPPORT_RATE_LIMIT_MAX
);

const toAscii = (value) => String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');

const normalizeSubject = (value) => {
    const normalized = cleanText(value, 40).toLowerCase();
    if (!normalized) return null;
    if (SUBJECTS.has(normalized)) return normalized;
    if (SUBJECT_ALIASES.has(normalized)) return SUBJECT_ALIASES.get(normalized);
    const ascii = toAscii(normalized);
    if (SUBJECTS.has(ascii)) return ascii;
    if (SUBJECT_ALIASES.has(ascii)) return SUBJECT_ALIASES.get(ascii);
    return null;
};

const parseTimestamp = (value) => {
    if (!value) return null;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return date.toISOString();
};

const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
        return forwarded.split(',')[0].trim().slice(0, 120);
    }
    return cleanText(req.ip || req.socket?.remoteAddress || '', 120) || null;
};

const getRateLimitKey = (req) => {
    if (req.authUser?.user_id) return `user:${req.authUser.user_id}`;
    const ip = getClientIp(req) || 'unknown';
    return `ip:${ip}`;
};

const supportLimiter = rateLimit({
    windowMs: SUPPORT_RATE_LIMIT_WINDOW_MS,
    max: SUPPORT_RATE_LIMIT_MAX,
    skipFailedRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        const key = getRateLimitKey(req);
        req.supportRateLimitKey = key;
        return key;
    },
    handler: (req, res) => {
        const rl = req.rateLimit || {};
        const resetDate = rl.resetTime ? new Date(rl.resetTime) : null;
        const resetIso = resetDate && !Number.isNaN(resetDate.getTime()) ? resetDate.toISOString() : null;
        console.warn('[support] rate_limited', {
            limitKey: req.supportRateLimitKey || getRateLimitKey(req),
            remaining: Number.isFinite(rl.remaining) ? rl.remaining : null,
            reset: resetIso,
            authUserPresent: Boolean(req.authUser)
        });
        return res.status(429).json({ error: 'Cok fazla sorun bildirimi. Lutfen daha sonra tekrar deneyin.' });
    }
});

const normalizeFileName = (value, fallback = 'attachment.bin') => {
    const cleaned = String(value || '')
        .trim()
        .replace(/[\\/:*?"<>|]+/g, '_')
        .replace(/\s+/g, '_')
        .slice(0, 120);
    return cleaned || fallback;
};

const authenticateOptional = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        req.authUser = null;
        return next();
    }

    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'Gecersiz oturum.' });

    try {
        const tokenHash = hashToken(token);
        const result = await pool.query(
            `SELECT s.user_id, u.username
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
            [tokenHash]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Oturum gecersiz veya suresi dolmus.' });
        }

        req.authUser = result.rows[0];
        next();
    } catch (e) {
        console.error('Support optional auth error:', e);
        res.status(500).json({ error: 'Sunucu hatasi.' });
    }
};

const readRequestBuffer = (req, maxBytes) => new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];

    req.on('data', (chunk) => {
        total += chunk.length;
        if (total > maxBytes) {
            reject(new Error('MULTIPART_TOO_LARGE'));
            req.destroy();
            return;
        }
        chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
    req.on('aborted', () => reject(new Error('REQUEST_ABORTED')));
});

const parseContentDisposition = (value) => {
    const result = { type: '', params: {} };
    const parts = String(value || '').split(';').map((v) => v.trim()).filter(Boolean);
    if (!parts.length) return result;
    result.type = parts[0].toLowerCase();
    parts.slice(1).forEach((part) => {
        const idx = part.indexOf('=');
        if (idx <= 0) return;
        const key = part.slice(0, idx).trim().toLowerCase();
        let val = part.slice(idx + 1).trim();
        if (val.startsWith('"') && val.endsWith('"')) {
            val = val.slice(1, -1);
        }
        result.params[key] = val;
    });
    return result;
};

const parseMultipartBody = (bodyBuffer, boundary) => {
    const bodyLatin = bodyBuffer.toString('latin1');
    const chunks = bodyLatin.split(`--${boundary}`);
    const fields = {};
    const files = [];

    chunks.forEach((chunk) => {
        if (!chunk || chunk === '--\r\n' || chunk === '--') return;
        let part = chunk;
        if (part.startsWith('\r\n')) part = part.slice(2);
        if (part.endsWith('\r\n')) part = part.slice(0, -2);
        if (part.endsWith('--')) part = part.slice(0, -2);
        if (!part) return;

        const sepIdx = part.indexOf('\r\n\r\n');
        if (sepIdx < 0) return;

        const rawHeaders = part.slice(0, sepIdx).split('\r\n');
        const contentLatin = part.slice(sepIdx + 4);
        const contentBuffer = Buffer.from(contentLatin, 'latin1');
        const headers = {};

        rawHeaders.forEach((line) => {
            const idx = line.indexOf(':');
            if (idx <= 0) return;
            const key = line.slice(0, idx).trim().toLowerCase();
            const val = line.slice(idx + 1).trim();
            headers[key] = val;
        });

        const disposition = parseContentDisposition(headers['content-disposition']);
        const fieldName = disposition.params.name;
        if (!fieldName) return;

        const fileName = disposition.params.filename || '';
        const mimeType = cleanText(headers['content-type'], 120).toLowerCase() || 'application/octet-stream';

        if (fieldName === 'media' && fileName) {
            files.push({
                fieldName,
                originalname: normalizeFileName(fileName),
                mimetype: mimeType,
                size: contentBuffer.length,
                buffer: contentBuffer
            });
            return;
        }

        fields[fieldName] = Buffer.from(contentBuffer).toString('utf8');
    });

    return { fields, files };
};

const parseSupportPayload = async (req) => {
    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    if (!contentType.includes('multipart/form-data')) {
        const body = req.body && typeof req.body === 'object' ? req.body : {};
        return {
            payload: {
                subject: body.subject,
                description: body.description,
                email: body.email,
                metadata: body.metadata
            },
            mediaFiles: []
        };
    }

    const boundaryMatch = contentType.match(/boundary=([^;]+)/i);
    const boundary = boundaryMatch?.[1]?.trim();
    if (!boundary) {
        const err = new Error('INVALID_MULTIPART');
        err.code = 'INVALID_MULTIPART';
        throw err;
    }

    const rawBuffer = await readRequestBuffer(req, MAX_MULTIPART_BODY_BYTES);
    const parsed = parseMultipartBody(rawBuffer, boundary.replace(/^"|"$/g, ''));
    let metadata = {};

    if (parsed.fields.metadata) {
        try {
            const maybeJson = JSON.parse(parsed.fields.metadata);
            metadata = maybeJson && typeof maybeJson === 'object' ? maybeJson : {};
        } catch {
            metadata = {};
        }
    }

    return {
        payload: {
            subject: parsed.fields.subject,
            description: parsed.fields.description,
            email: parsed.fields.email,
            metadata
        },
        mediaFiles: parsed.files || []
    };
};

const validateMediaFiles = (files = []) => {
    if (!Array.isArray(files)) return [];
    if (files.length > MAX_FILES) {
        const err = new Error(`En fazla ${MAX_FILES} medya dosyasi ekleyebilirsiniz.`);
        err.code = 'MEDIA_FILE_COUNT_LIMIT';
        throw err;
    }

    let totalBytes = 0;
    const normalized = files.map((file, index) => {
        const mimeType = cleanText(file.mimetype, 120).toLowerCase();
        const size = Number(file.size) || 0;
        if (!MIME_RE.test(mimeType)) {
            const err = new Error(`Desteklenmeyen medya tipi: ${mimeType || 'unknown'}`);
            err.code = 'MEDIA_MIME_INVALID';
            throw err;
        }
        if (size <= 0) {
            const err = new Error('Bos medya dosyasi kabul edilmez.');
            err.code = 'MEDIA_EMPTY_FILE';
            throw err;
        }
        if (size > MAX_FILE_BYTES) {
            const err = new Error(`Tek dosya boyutu en fazla ${Math.round(MAX_FILE_BYTES / (1024 * 1024))} MB olabilir.`);
            err.code = 'MEDIA_FILE_SIZE_LIMIT';
            throw err;
        }
        totalBytes += size;
        if (totalBytes > MAX_TOTAL_FILE_BYTES) {
            const err = new Error(`Toplam medya boyutu en fazla ${Math.round(MAX_TOTAL_FILE_BYTES / (1024 * 1024))} MB olabilir.`);
            err.code = 'MEDIA_TOTAL_SIZE_LIMIT';
            throw err;
        }

        return {
            fileName: normalizeFileName(file.originalname, `report-media-${index + 1}`),
            mimeType,
            sizeBytes: size,
            mediaKind: mimeType.startsWith('image/') ? 'image' : 'video',
            buffer: file.buffer
        };
    });

    return normalized;
};

router.post('/report', authenticateOptional, supportLimiter, async (req, res) => {
    let requestData = null;
    try {
        requestData = await parseSupportPayload(req);
    } catch (e) {
        if (e.message === 'MULTIPART_TOO_LARGE') {
            return res.status(400).json({ error: 'Medya boyutu limiti asildi.' });
        }
        if (e.code === 'INVALID_MULTIPART') {
            return res.status(400).json({ error: 'Gecersiz medya istegi.' });
        }
        console.error('Support payload parse error:', e);
        return res.status(400).json({ error: 'Sorun bildirimi verisi okunamadi.' });
    }

    const body = requestData?.payload || {};
    const subjectRaw = cleanText(body.subject, 40);
    const subject = normalizeSubject(subjectRaw);
    const description = cleanText(body.description, MAX_DESCRIPTION);
    const email = cleanText(body.email, 254);
    const metadata = body?.metadata && typeof body.metadata === 'object' ? body.metadata : {};

    if (!SUBJECTS.has(subject)) {
        console.warn('[support] invalid_subject', {
            contentType: cleanText(req.headers['content-type'], 120) || null,
            subjectRaw: subjectRaw || null,
            subjectNormalized: subject || null,
            hasAuthUser: Boolean(req.authUser),
            ipHint: getClientIp(req)
        });
        return res.status(400).json({ error: 'Gecersiz konu secimi.' });
    }

    if (!description || description.length < 10) {
        return res.status(400).json({ error: 'Aciklama en az 10 karakter olmali.' });
    }

    if (email && !EMAIL_RE.test(email)) {
        return res.status(400).json({ error: 'E-posta formati gecersiz.' });
    }

    let mediaItems = [];
    try {
        mediaItems = validateMediaFiles(requestData?.mediaFiles || []);
    } catch (e) {
        return res.status(400).json({ error: e.message || 'Medya dogrulamasi basarisiz.' });
    }

    const appVersion = cleanText(metadata.appVersion, 80) || null;
    const platform = cleanText(metadata.platform, 40) || null;
    const deviceModel = cleanText(metadata.deviceModel, 120) || null;
    const clientTimestamp = parseTimestamp(metadata.timestamp);
    const networkType = cleanText(metadata.networkType, 30) || null;
    const lastErrorCode = cleanText(metadata.lastErrorCode, 120) || null;
    const userAgent = cleanText(req.headers['user-agent'], 400) || null;
    const ip = getClientIp(req);
    const contactEmail = email || null;
    const userId = req.authUser?.user_id || null;
    const usernameSnapshot = req.authUser?.username || null;

    let reportId = null;
    let createdAt = null;

    const dbClient = await pool.connect();
    try {
        await dbClient.query('BEGIN');
        const insertResult = await dbClient.query(
            `INSERT INTO support_reports
              (subject, description, contact_email, user_id, username_snapshot, app_version, platform, device_model, client_timestamp, network_type, last_error_code, ip, user_agent, brevo_status, updated_at)
             VALUES
              ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending', NOW())
             RETURNING id, created_at`,
            [
                subject,
                description,
                contactEmail,
                userId,
                usernameSnapshot,
                appVersion,
                platform,
                deviceModel,
                clientTimestamp,
                networkType,
                lastErrorCode,
                ip,
                userAgent
            ]
        );

        reportId = insertResult.rows[0].id;
        createdAt = insertResult.rows[0].created_at;

        for (const item of mediaItems) {
            await dbClient.query(
                `INSERT INTO support_report_media
                  (report_id, mime_type, file_name, size_bytes, media_kind, data)
                 VALUES
                  ($1, $2, $3, $4, $5, $6)`,
                [
                    reportId,
                    item.mimeType,
                    item.fileName,
                    item.sizeBytes,
                    item.mediaKind,
                    item.buffer
                ]
            );
        }

        await dbClient.query('COMMIT');
    } catch (e) {
        await dbClient.query('ROLLBACK');
        console.error('Support report create error:', e);
        return res.status(500).json({ error: 'Sorun bildirimi alinamadi.' });
    } finally {
        dbClient.release();
    }

    try {
        const mailResult = await sendSupportReportEmail({
            reportId,
            subject,
            description,
            contactEmail,
            userId,
            username: usernameSnapshot,
            appVersion,
            platform,
            deviceModel,
            clientTimestamp,
            networkType,
            lastErrorCode,
            ip,
            userAgent,
            createdAt,
            attachments: mediaItems
        });

        await pool.query(
            `UPDATE support_reports
             SET brevo_status = 'sent', brevo_message_id = $2, brevo_error = NULL, updated_at = NOW()
             WHERE id = $1`,
            [reportId, cleanText(mailResult?.messageId, 180) || null]
        );

        return res.status(201).json({
            success: true,
            reportId,
            delivered: true
        });
    } catch (mailError) {
        const brevoError = cleanText(mailError?.message || 'Brevo send failed', 500);
        console.error('Support mail send error:', brevoError);

        await pool.query(
            `UPDATE support_reports
             SET brevo_status = 'failed', brevo_error = $2, updated_at = NOW()
             WHERE id = $1`,
            [reportId, brevoError]
        );

        return res.status(202).json({
            success: true,
            reportId,
            delivered: false
        });
    }
});

module.exports = router;
