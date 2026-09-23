const createRetentionRunner = ({ pool, registry, lockId = 730006, now = () => new Date() }) => {
    const run = async ({ mode = 'dry_run', policyVersion, executeApproved = false } = {}) => {
        if (!['dry_run', 'execute'].includes(mode)) throw Object.assign(new Error('Invalid retention mode'), { code: 'RETENTION_MODE_INVALID' });
        if (mode === 'execute' && !executeApproved) throw Object.assign(new Error('Execute approval required'), { code: 'RETENTION_EXECUTE_NOT_APPROVED' });
        const reviewBlockers = registry.filter((item) => item.reviewState === 'checkpoint_required');
        if (mode === 'execute' && reviewBlockers.length) throw Object.assign(new Error('Policy owner review required'), { code: 'RETENTION_POLICY_INCOMPLETE' });
        const client = await pool.connect();
        const runId = require('crypto').randomUUID();
        try {
            const lock = await client.query('SELECT pg_try_advisory_lock($1) AS locked', [lockId]);
            if (!lock.rows?.[0]?.locked) return { runId, status: 'skipped_locked', mode, policyVersion };
            const result = {
                runId, status: mode === 'dry_run' ? 'previewed' : 'executed', mode, policyVersion,
                cutoff: now().toISOString(), classes: registry.map((item) => ({ dataClassKey: item.dataClassKey, action: item.expiryAction }))
            };
            return result;
        } finally {
            try { await client.query('SELECT pg_advisory_unlock($1)', [lockId]); } finally { client.release(); }
        }
    };
    return { run };
};

module.exports = { createRetentionRunner };
