const { registry } = require('./dataPolicyRegistry');

const claims = Object.freeze([
    { claimKey: 'privacy.account', dataClasses: ['account.identity','account.session','legal.acceptance'], evidence: ['db.js','routes/auth.js','routes/profile.js'], reviewState: 'checkpoint_required' },
    { claimKey: 'privacy.messaging', dataClasses: ['message.anonymous','message.friend','media.ephemeral'], evidence: ['index.js'], reviewState: 'checkpoint_required' },
    { claimKey: 'privacy.safety_support', dataClasses: ['trust.moderation','support.case'], evidence: ['moderation.js','routes/support.js','admin.js'], reviewState: 'checkpoint_required' },
    { claimKey: 'privacy.push', dataClasses: ['push.delivery'], evidence: ['utils/push.js'], processor: 'Firebase', region: 'verification_required', reviewState: 'checkpoint_required' },
    { claimKey: 'privacy.support_delivery', dataClasses: ['support.case'], evidence: ['utils/brevoSupport.js'], processor: 'Brevo', region: 'verification_required', reviewState: 'checkpoint_required' },
    { claimKey: 'privacy.geo_country', dataClasses: ['legal.acceptance','match.country'], evidence: ['admin.js','utils/countryPolicy.js'], processor: 'geo provider chain', region: 'verification_required', reviewState: 'checkpoint_required' },
    { claimKey: 'privacy.telemetry', dataClasses: ['telemetry.performance','telemetry.behavior'], evidence: ['index.js'], reviewState: 'checkpoint_required' },
    { claimKey: 'privacy.infrastructure', dataClasses: ['infra.backup','infra.application_log'], evidence: ['docs/WAVE04_BACKUP_RESTORE_RUNBOOK.md'], processor: 'hosting/database', region: 'verification_required', reviewState: 'checkpoint_required' },
    { claimKey: 'privacy.account_deletion', dataClasses: ['deletion.operation'], evidence: ['utils/accountDeletion.js','routes/profile.js'], reviewState: 'checkpoint_required' }
]);

const validatePrivacyClaims = ({ release = false } = {}) => {
    const known = new Set(registry.map((item) => item.dataClassKey));
    const errors = [];
    for (const claim of claims) {
        for (const key of claim.dataClasses) if (!known.has(key)) errors.push(`${claim.claimKey}:unknown:${key}`);
        if (release && claim.reviewState === 'checkpoint_required') errors.push(`${claim.claimKey}:human_review_required`);
        if (release && claim.region === 'verification_required') errors.push(`${claim.claimKey}:region_verification_required`);
    }
    return { ok: errors.length === 0, errors, claimCount: claims.length };
};

module.exports = { claims, validatePrivacyClaims };
