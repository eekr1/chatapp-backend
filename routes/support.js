const express = require('express');
const rateLimit = require('express-rate-limit');
const { pool } = require('../db');
const { hashToken } = require('../utils/security');
const { sendSupportReportEmail } = require('../utils/brevoSupport');

const router = express.Router();

const SUBJECTS = new Set(['connection', 'message', 'photo', 'other']);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_DESCRIPTION = 2000;

const supportLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Cok fazla sorun bildirimi. Lutfen daha sonra tekrar deneyin.' }
});

const cleanText = (value, max = 1000) => {
    if (typeof value !== 'string') return '';
    return value.trim().slice(0, max);
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

router.post('/report', supportLimiter, authenticateOptional, async (req, res) => {
    const subject = cleanText(req.body.subject, 40).toLowerCase();
    const description = cleanText(req.body.description, MAX_DESCRIPTION);
    const email = cleanText(req.body.email, 254);
    const metadata = req.body?.metadata && typeof req.body.metadata === 'object' ? req.body.metadata : {};

    if (!SUBJECTS.has(subject)) {
        return res.status(400).json({ error: 'Gecersiz konu secimi.' });
    }

    if (!description || description.length < 10) {
        return res.status(400).json({ error: 'Aciklama en az 10 karakter olmali.' });
    }

    if (email && !EMAIL_RE.test(email)) {
        return res.status(400).json({ error: 'E-posta formati gecersiz.' });
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
    try {
        const insertResult = await pool.query(
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
        const createdAt = insertResult.rows[0].created_at;

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
                createdAt
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
    } catch (e) {
        console.error('Support report create error:', e);
        res.status(500).json({ error: 'Sorun bildirimi alinamadi.' });
    }
});

module.exports = router;
