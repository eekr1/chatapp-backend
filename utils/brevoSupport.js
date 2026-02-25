const https = require('https');

const BREVO_API_HOST = 'api.brevo.com';
const BREVO_API_PATH = '/v3/smtp/email';

const SUBJECT_LABELS = {
    connection: 'Baglanti',
    message: 'Mesaj',
    photo: 'Foto',
    other: 'Diger'
};

const cleanText = (value, max = 1000) => {
    if (typeof value !== 'string') return '';
    return value.trim().slice(0, max);
};

const parseEmails = (value) => String(value || '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);

const isValidEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());

const buildTextBody = (report = {}) => {
    const subjectLabel = SUBJECT_LABELS[report.subject] || report.subject || 'Diger';
    const lines = [
        'TalkX Support Report',
        '',
        `Report ID: ${report.reportId || '-'}`,
        `Subject: ${subjectLabel}`,
        `Created At: ${report.createdAt || '-'}`,
        `User ID: ${report.userId || '-'}`,
        `Username: ${report.username || '-'}`,
        `Contact Email: ${report.contactEmail || '-'}`,
        '',
        'Description:',
        report.description || '-',
        '',
        'Client Metadata:',
        `- App Version: ${report.appVersion || '-'}`,
        `- Platform: ${report.platform || '-'}`,
        `- Device Model: ${report.deviceModel || '-'}`,
        `- Client Time: ${report.clientTimestamp || '-'}`,
        `- Network Type: ${report.networkType || '-'}`,
        `- Last Error Code: ${report.lastErrorCode || '-'}`,
        '',
        'Request Metadata:',
        `- IP: ${report.ip || '-'}`,
        `- User-Agent: ${report.userAgent || '-'}`
    ];
    return lines.join('\n');
};

const postBrevoMail = (payload, apiKey) => new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const request = https.request({
        hostname: BREVO_API_HOST,
        path: BREVO_API_PATH,
        method: 'POST',
        headers: {
            'accept': 'application/json',
            'content-type': 'application/json',
            'api-key': apiKey,
            'content-length': Buffer.byteLength(body)
        }
    }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf8');
            let parsed = {};
            try {
                parsed = raw ? JSON.parse(raw) : {};
            } catch {
                parsed = { raw };
            }

            if (response.statusCode >= 200 && response.statusCode < 300) {
                return resolve(parsed);
            }

            const error = new Error(parsed.message || `Brevo request failed (${response.statusCode})`);
            error.statusCode = response.statusCode;
            error.response = parsed;
            reject(error);
        });
    });

    request.on('error', reject);
    request.write(body);
    request.end();
});

const resolveConfig = () => {
    const apiKey = cleanText(process.env.BREVO_API_KEY, 500);
    const fromEmail = cleanText(process.env.SUPPORT_FROM_EMAIL, 254);
    const fromName = cleanText(process.env.SUPPORT_FROM_NAME || 'TalkX Support', 120);
    const subjectPrefix = cleanText(process.env.SUPPORT_SUBJECT_PREFIX || '[TalkX Support]', 120);
    const toEmails = parseEmails(process.env.SUPPORT_TO_EMAILS).filter(isValidEmail);

    if (!apiKey || !fromEmail || !isValidEmail(fromEmail) || toEmails.length === 0) {
        const error = new Error('Brevo support mail config is missing.');
        error.code = 'BREVO_CONFIG_MISSING';
        throw error;
    }

    return {
        apiKey,
        fromEmail,
        fromName,
        subjectPrefix,
        toEmails
    };
};

const sendSupportReportEmail = async (report = {}) => {
    const config = resolveConfig();
    const subjectLabel = SUBJECT_LABELS[report.subject] || report.subject || 'Diger';
    const payload = {
        sender: {
            email: config.fromEmail,
            name: config.fromName
        },
        to: config.toEmails.map((email) => ({ email })),
        subject: `${config.subjectPrefix} ${subjectLabel}`.trim(),
        textContent: buildTextBody(report)
    };

    if (report.contactEmail && isValidEmail(report.contactEmail)) {
        payload.replyTo = { email: report.contactEmail };
    }

    const result = await postBrevoMail(payload, config.apiKey);
    return {
        messageId: result?.messageId || null
    };
};

module.exports = {
    sendSupportReportEmail
};
