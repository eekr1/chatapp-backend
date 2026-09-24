const crypto = require('crypto');
const { fetchLegalSettings, normalizeLegalContent } = require('./legalContent');

const normalizeVersion = (value, fallback = 'v1') => {
    if (typeof value !== 'string') return fallback;
    const trimmed = value.trim();
    return trimmed || fallback;
};

const hashJson = (value) => crypto.createHash('sha256')
    .update(JSON.stringify(value), 'utf8')
    .digest('hex');

const buildLegalRelease = ({ item, updatedAt = null } = {}) => {
    const content = normalizeLegalContent(item);
    const checksum = hashJson(content);
    return {
        releaseId: `legal-${checksum.slice(0, 24)}`,
        revision: checksum,
        checksum,
        publishedAt: updatedAt || null,
        format: 'plain_text',
        required: {
            terms: normalizeVersion(content.versions?.terms, 'v1'),
            privacy: normalizeVersion(content.versions?.privacy, 'v1')
        },
        content
    };
};

const buildRequirementFingerprint = (required = {}) => hashJson({
    terms: normalizeVersion(required.terms, ''),
    privacy: normalizeVersion(required.privacy, '')
});

const getRequiredLegalState = async (db, { lock = false } = {}) => {
    const { item, updatedAt } = await fetchLegalSettings(db, { lock });
    return buildLegalRelease({ item, updatedAt });
};

const getRequiredLegalVersions = async (db) => (await getRequiredLegalState(db)).required;

const getLatestLegalAcceptance = async (db, userId) => {
    if (!userId) return null;
    const result = await db.query(
        `SELECT terms_version, privacy_version, accepted_at, release_id, release_revision,
                requirement_fingerprint, command_id, locale
         FROM legal_acceptances
         WHERE user_id = $1
         ORDER BY accepted_at DESC
         LIMIT 1`,
        [userId]
    );
    if (!result.rows.length) return null;
    const row = result.rows[0];
    return {
        terms: normalizeVersion(row.terms_version, ''),
        privacy: normalizeVersion(row.privacy_version, ''),
        accepted_at: row.accepted_at || null,
        release_id: row.release_id || null,
        release_revision: row.release_revision || null,
        requirement_fingerprint: row.requirement_fingerprint || null,
        command_id: row.command_id || null,
        locale: row.locale || null
    };
};

const getReacceptReason = (required, accepted) => {
    if (!accepted) return 'missing_acceptance';
    const termsChanged = accepted.terms !== required.terms;
    const privacyChanged = accepted.privacy !== required.privacy;
    if (termsChanged && privacyChanged) return 'multiple';
    if (termsChanged) return 'terms_changed';
    if (privacyChanged) return 'privacy_changed';
    return null;
};

const calculateLegalStatus = async (db, userId) => {
    const release = await getRequiredLegalState(db);
    const latestAcceptance = await getLatestLegalAcceptance(db, userId);
    const reason = getReacceptReason(release.required, latestAcceptance);

    return {
        releaseId: release.releaseId,
        revision: release.revision,
        publishedAt: release.publishedAt,
        required: release.required,
        accepted: latestAcceptance,
        requiresReaccept: Boolean(reason),
        reason,
        checkedAt: new Date().toISOString()
    };
};

const acceptLegalRequirement = async ({
    pool,
    userId,
    expectedReleaseId,
    termsVersion,
    privacyVersion,
    commandId,
    locale = null,
    ip = null,
    userAgent = null
}) => {
    const db = await pool.connect();
    try {
        await db.query('BEGIN');
        const release = await getRequiredLegalState(db, { lock: true });
        if (expectedReleaseId !== release.releaseId
            || termsVersion !== release.required.terms
            || privacyVersion !== release.required.privacy) {
            const error = new Error('Legal release changed.');
            error.code = 'LEGAL_VERSION_MISMATCH';
            error.status = 409;
            error.legalState = release;
            throw error;
        }

        const fingerprint = buildRequirementFingerprint(release.required);
        const commandReplay = await db.query(
            `SELECT terms_version,privacy_version,accepted_at,release_id,release_revision,
                    requirement_fingerprint,command_id,locale
             FROM legal_acceptances WHERE user_id=$1 AND command_id=$2 LIMIT 1`,
            [userId, commandId]
        );
        if (commandReplay.rows.length && commandReplay.rows[0].requirement_fingerprint !== fingerprint) {
            const error = new Error('Acceptance command identity conflict.');
            error.code = 'IDEMPOTENCY_CONFLICT';
            error.status = 409;
            throw error;
        }

        let row = commandReplay.rows[0] || null;
        let replayed = Boolean(row);
        if (!row) {
            const result = await db.query(
                `INSERT INTO legal_acceptances
                  (user_id,terms_version,privacy_version,accepted_at,ip,user_agent,release_id,release_revision,requirement_fingerprint,command_id,locale)
                 VALUES ($1,$2,$3,NOW(),$4,$5,$6,$7,$8,$9,$10)
                 ON CONFLICT (user_id,requirement_fingerprint) WHERE requirement_fingerprint IS NOT NULL
                 DO NOTHING
                 RETURNING terms_version,privacy_version,accepted_at,release_id,release_revision,requirement_fingerprint,command_id,locale`,
                [userId, release.required.terms, release.required.privacy, ip, userAgent,
                    release.releaseId, release.revision, fingerprint, commandId, locale]
            );
            row = result.rows[0] || null;
            if (!row) {
                const existing = await db.query(
                    `SELECT terms_version,privacy_version,accepted_at,release_id,release_revision,
                            requirement_fingerprint,command_id,locale
                     FROM legal_acceptances WHERE user_id=$1 AND requirement_fingerprint=$2 LIMIT 1`,
                    [userId, fingerprint]
                );
                row = existing.rows[0];
                replayed = true;
            }
        }

        await db.query('COMMIT');
        return {
            replayed,
            releaseId: release.releaseId,
            revision: release.revision,
            required: release.required,
            accepted: {
                terms: row.terms_version,
                privacy: row.privacy_version,
                accepted_at: row.accepted_at,
                release_id: row.release_id,
                release_revision: row.release_revision,
                locale: row.locale || null
            }
        };
    } catch (error) {
        try { await db.query('ROLLBACK'); } catch { /* ignore rollback errors */ }
        throw error;
    } finally {
        db.release();
    }
};

const legalStatusPayload = (status) => ({
    release_id: status?.releaseId || null,
    revision: status?.revision || null,
    published_at: status?.publishedAt || null,
    required_versions: status?.required || null,
    accepted_versions: status?.accepted || null,
    requires_reaccept: Boolean(status?.requiresReaccept),
    reason: status?.reason || null,
    checked_at: status?.checkedAt || new Date().toISOString()
});

module.exports = {
    buildLegalRelease,
    buildRequirementFingerprint,
    getRequiredLegalState,
    getRequiredLegalVersions,
    getLatestLegalAcceptance,
    calculateLegalStatus,
    acceptLegalRequirement,
    legalStatusPayload
};
