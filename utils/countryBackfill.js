const { evaluateCountryCandidate, POLICY_VERSION } = require('./countryPolicy');

const planCountryBackfill = ({ candidates = [], existing = new Map(), now = new Date() }) => {
    const grouped = new Map();
    for (const row of candidates) {
        const userId = String(row.user_id || '');
        if (!userId) continue;
        const evaluated = evaluateCountryCandidate({
            country: row.location_country,
            source: row.location_source,
            observedAt: row.location_resolved_at || row.accepted_at,
            now
        });
        if (!grouped.has(userId)) grouped.set(userId, []);
        grouped.get(userId).push({ ...evaluated, observedAt: row.location_resolved_at || row.accepted_at || null });
    }
    const writes = [];
    const counts = { eligible: 0, stale: 0, unavailable: 0, disputed: 0, skippedNewer: 0 };
    for (const [userId, items] of grouped) {
        const current = existing.get(userId);
        const newest = items.sort((a, b) => new Date(b.observedAt || 0) - new Date(a.observedAt || 0))[0];
        if (current?.updated_at && newest?.observedAt && new Date(current.updated_at) >= new Date(newest.observedAt)) {
            counts.skippedNewer += 1;
            continue;
        }
        const eligibleCodes = new Set(items.filter((item) => item.status === 'eligible').map((item) => item.countryCode));
        const result = eligibleCodes.size > 1
            ? { countryCode: null, status: 'disputed', confidence: 'unknown', policyVersion: POLICY_VERSION, observedAt: newest?.observedAt || null }
            : newest;
        if (current?.status === 'eligible' && result?.status !== 'eligible') {
            counts.skippedNewer += 1;
            continue;
        }
        counts[result.status] += 1;
        writes.push({ userId, ...result });
    }
    return { policyVersion: POLICY_VERSION, writes, counts };
};

module.exports = { planCountryBackfill };
