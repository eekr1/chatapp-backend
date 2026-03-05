const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
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
const MAX_MULTIPART_FIELD_SIZE = 64 * 1024; // 64 KB per text field
const MAX_MULTIPART_FIELDS = 12;
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
            `SELECT s.user_id, u.username, u.status
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
            [tokenHash]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Oturum gecersiz veya suresi dolmus.' });
        }
        if (result.rows[0].status !== 'active') {
            return res.status(403).json({ error: 'Hesap aktif degil.' });
        }

        req.authUser = result.rows[0];
        next();
    } catch (e) {
        console.error('Support optional auth error:', e);
        res.status(500).json({ error: 'Sunucu hatasi.' });
    }
};

const isMultipartRequest = (req) => String(req.headers['content-type'] || '')
    .toLowerCase()
    .includes('multipart/form-data');

const supportUpload = multer({
    storage: multer.memoryStorage(),
    limits: {
        files: MAX_FILES,
        fileSize: MAX_FILE_BYTES,
        fields: MAX_MULTIPART_FIELDS,
        fieldSize: MAX_MULTIPART_FIELD_SIZE
    }
});

const parseSupportMetadata = (value) => {
    if (!value) return {};
    if (typeof value === 'object' && !Array.isArray(value)) return value;
    if (typeof value !== 'string') return {};
    try {
        const parsed = JSON.parse(value);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
        return parsed;
    } catch {
        return {};
    }
};

const handleSupportMulterError = (err, req, res) => {
    if (!(err instanceof multer.MulterError)) {
        console.error('Support multipart parse error:', err);
        return res.status(400).json({
            error: 'Sorun bildirimi verisi okunamadi.',
            code: 'MULTIPART_PARSE_FAILED'
        });
    }

    switch (err.code) {
        case 'LIMIT_FILE_SIZE':
            return res.status(400).json({
                error: `Tek dosya boyutu en fazla ${Math.round(MAX_FILE_BYTES / (1024 * 1024))} MB olabilir.`,
                code: 'MEDIA_FILE_SIZE_LIMIT'
            });
        case 'LIMIT_FILE_COUNT':
            return res.status(400).json({
                error: `En fazla ${MAX_FILES} medya dosyasi ekleyebilirsiniz.`,
                code: 'MEDIA_FILE_COUNT_LIMIT'
            });
        case 'LIMIT_UNEXPECTED_FILE':
            return res.status(400).json({
                error: 'Gecersiz medya alani.',
                code: 'MEDIA_UNEXPECTED_FIELD'
            });
        case 'LIMIT_FIELD_VALUE':
        case 'LIMIT_FIELD_COUNT':
        case 'LIMIT_PART_COUNT':
            return res.status(400).json({
                error: 'Medya istegindeki alanlar gecersiz veya fazla buyuk.',
                code: 'MULTIPART_FIELDS_INVALID'
            });
        default:
            console.error('Support multipart multer error:', {
                code: err.code,
                message: err.message
            });
            return res.status(400).json({
                error: 'Sorun bildirimi verisi okunamadi.',
                code: 'MULTIPART_PARSE_FAILED'
            });
    }
};

const supportUploadMiddleware = (req, res, next) => {
    if (!isMultipartRequest(req)) return next();
    return supportUpload.array('media', MAX_FILES)(req, res, (err) => {
        if (!err) return next();
        return handleSupportMulterError(err, req, res);
    });
};

const parseSupportPayload = (req) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    return {
        payload: {
            subject: body.subject,
            description: body.description,
            email: body.email,
            metadata: parseSupportMetadata(body.metadata)
        },
        mediaFiles: Array.isArray(req.files) ? req.files : []
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

router.post('/report', authenticateOptional, supportLimiter, supportUploadMiddleware, async (req, res) => {
    const requestData = parseSupportPayload(req);

    const body = requestData?.payload || {};
    const subjectRaw = cleanText(body.subject, 40);
    const subject = normalizeSubject(subjectRaw);
    const description = cleanText(body.description, MAX_DESCRIPTION);
    const email = cleanText(body.email, 254);
    const metadata = body?.metadata && typeof body.metadata === 'object' ? body.metadata : {};

    if (!SUBJECTS.has(subject)) {
        const bodyKeys = body && typeof body === 'object'
            ? Object.keys(body).slice(0, 20)
            : [];
        console.warn('[support] invalid_subject', {
            isMultipart: isMultipartRequest(req),
            bodyKeys,
            filesCount: Array.isArray(requestData?.mediaFiles) ? requestData.mediaFiles.length : 0,
            contentType: cleanText(req.headers['content-type'], 120) || null,
            subjectRaw: subjectRaw || null,
            subjectNormalized: subject || null,
            hasAuthUser: Boolean(req.authUser),
            ipHint: getClientIp(req)
        });
        return res.status(400).json({
            error: 'Gecersiz konu secimi.',
            code: 'INVALID_SUBJECT'
        });
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
        return res.status(400).json({
            error: e.message || 'Medya dogrulamasi basarisiz.',
            code: e.code || 'MEDIA_VALIDATION_FAILED'
        });
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
