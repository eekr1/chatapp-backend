const { fetchLegalSettings } = require('./legalContent');

const normalizeVersion = (value, fallback = 'v1') => {
    if (typeof value !== 'string') return fallback;
    const trimmed = value.trim();
    return trimmed || fallback;
};

const getRequiredLegalVersions = async (pool) => {
    const { item } = await fetchLegalSettings(pool);
    return {
        terms: normalizeVersion(item?.versions?.terms, 'v1'),
        privacy: normalizeVersion(item?.versions?.privacy, 'v1')
    };
};

const getLatestLegalAcceptance = async (pool, userId) => {
    if (!userId) return null;
    const result = await pool.query(
        `SELECT terms_version, privacy_version, accepted_at
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
        accepted_at: row.accepted_at || null
    };
};

const calculateLegalStatus = async (pool, userId) => {
    const requiredVersions = await getRequiredLegalVersions(pool);
    const latestAcceptance = await getLatestLegalAcceptance(pool, userId);
    const requiresReaccept = !latestAcceptance
        || latestAcceptance.terms !== requiredVersions.terms
        || latestAcceptance.privacy !== requiredVersions.privacy;

    return {
        required: requiredVersions,
        accepted: latestAcceptance,
        requiresReaccept
    };
};

module.exports = {
    getRequiredLegalVersions,
    getLatestLegalAcceptance,
    calculateLegalStatus
};
