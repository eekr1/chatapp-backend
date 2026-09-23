const POLICY_VERSION = 'talkx-data-policy-v1';

const base = {
    productOwner: 'TalkX product owner',
    technicalOwner: 'TalkX backend owner',
    adminAccess: 'least-privilege; masked by default; reveal/export requires reason and audit',
    legalHoldPolicy: 'allowlisted reason, named owner, approval and finite expiry required',
    backupBehavior: 'encrypted bounded artifact; erasure journal replay required before restore cutover',
    policyVersion: POLICY_VERSION
};
const entry = (dataClassKey, stores, purpose, retentionDuration, expiryAction, accountDeletionAction, extra = {}) => Object.freeze({
    ...base, dataClassKey, stores, purpose, dataSubject: 'account', sensitivity: 'personal',
    collectionSource: 'client_or_server', retentionStart: 'record lifecycle event', retentionDuration,
    expiryAction, accountDeletionAction, processorsAndRegions: [], evidenceQuery: `registry:${dataClassKey}`, ...extra
});

const registry = Object.freeze([
    entry('account.identity', ['users', 'profiles'], 'authentication and profile', 'until account deletion', 'delete', 'delete'),
    entry('account.anonymous_identity', ['users_anon'], 'legacy anonymous device identity', 'owner decision required', 'review_required', 'delete_or_anonymize', { reviewState: 'checkpoint_required' }),
    entry('account.session', ['sessions', 'connection_leases', 'process:realtime'], 'authenticated access and presence', 'session expiry or revocation', 'delete', 'delete'),
    entry('match.country', ['user_match_country'], 'server-authoritative future matchmaking eligibility', 'until refresh or account deletion', 'replace_or_delete', 'delete'),
    entry('social.relationship', ['friendships', 'blocks'], 'friend and safety relationships', 'until relationship end or account deletion', 'delete', 'delete'),
    entry('message.anonymous', ['conversations', 'process:anonymous-room'], 'temporary anonymous conversation', 'room lifecycle', 'delete', 'delete'),
    entry('message.friend', ['conversations', 'messages'], 'persistent friend conversation history', 'owner decision required', 'review_required', 'anonymize_or_delete', { reviewState: 'checkpoint_required' }),
    entry('media.ephemeral', ['ephemeral_media'], 'single-use media', 'view/expiry lifecycle', 'delete', 'delete', { sensitivity: 'restricted' }),
    entry('trust.moderation', ['reports', 'bans'], 'abuse prevention and moderation evidence', 'owner decision required', 'review_required', 'pseudonymize_and_retain_minimum', { reviewState: 'checkpoint_required', sensitivity: 'restricted' }),
    entry('support.case', ['support_reports', 'support_report_media', 'processor:brevo'], 'user support and delivery', 'owner decision required', 'review_required', 'anonymize_or_delete', { reviewState: 'checkpoint_required', sensitivity: 'restricted' }),
    entry('push.delivery', ['push_devices', 'push_delivery_logs', 'processor:firebase'], 'push registration and delivery diagnostics', 'token lifecycle; logs owner decision required', 'deactivate_or_delete', 'delete_or_anonymize', { reviewState: 'checkpoint_required' }),
    entry('legal.acceptance', ['legal_acceptances'], 'versioned legal acceptance evidence', 'owner decision required', 'review_required', 'pseudonymize_or_retain_minimum', { reviewState: 'checkpoint_required', sensitivity: 'restricted' }),
    entry('telemetry.performance', ['http_request_events', 'http_request_metrics_minute'], 'service reliability', '7 days raw; 30 days aggregate', 'delete', 'aggregate'),
    entry('telemetry.behavior', ['behavior_events'], 'bounded product behavior analytics', 'configured 7-365 days; default 90', 'delete', 'anonymize'),
    entry('admin.audit', ['admin_action_audit'], 'security and destructive-action accountability', 'owner decision required', 'immutable_review_required', 'pseudonymize_and_retain_minimum', { reviewState: 'checkpoint_required', sensitivity: 'restricted' }),
    entry('deletion.operation', ['account_deletion_requests', 'account_deletion_steps', 'erasure_journal'], 'idempotent deletion evidence and restore protection', 'owner decision required', 'review_required', 'retain_minimum_receipt', { reviewState: 'checkpoint_required', sensitivity: 'restricted' }),
    entry('config.schedule', ['app_settings', 'notification_schedules'], 'application configuration', 'until superseded', 'replace_or_archive', 'not_applicable', { dataSubject: 'system', sensitivity: 'internal' }),
    entry('infra.backup', ['backup:postgresql'], 'disaster recovery', 'artifact expiry set by named owner', 'delete_artifact', 'replay_erasure_before_cutover', { dataSubject: 'mixed', sensitivity: 'restricted', reviewState: 'checkpoint_required' }),
    entry('infra.application_log', ['runtime:stdout'], 'security and operations diagnostics', 'platform setting; owner verification required', 'delete', 'anonymize', { dataSubject: 'mixed', reviewState: 'checkpoint_required' })
]);

const validateRegistry = ({ release = false } = {}) => {
    const errors = [];
    const keys = new Set();
    const required = ['dataClassKey','stores','purpose','productOwner','technicalOwner','retentionStart','retentionDuration','expiryAction','accountDeletionAction','adminAccess','backupBehavior','policyVersion'];
    for (const item of registry) {
        if (keys.has(item.dataClassKey)) errors.push(`duplicate:${item.dataClassKey}`);
        keys.add(item.dataClassKey);
        for (const field of required) if (!item[field] || (Array.isArray(item[field]) && !item[field].length)) errors.push(`${item.dataClassKey}:${field}`);
        if (/\bTBD\b/i.test(JSON.stringify(item))) errors.push(`${item.dataClassKey}:TBD`);
        if (release && item.reviewState === 'checkpoint_required') errors.push(`${item.dataClassKey}:owner_review_required`);
    }
    return { ok: errors.length === 0, errors, policyVersion: POLICY_VERSION, classCount: registry.length };
};

const validateStoreCoverage = (stores) => {
    const covered = new Set(registry.flatMap((item) => item.stores));
    const missing = [...stores].filter((store) => !covered.has(store));
    return { ok: missing.length === 0, missing };
};

module.exports = { POLICY_VERSION, registry, validateRegistry, validateStoreCoverage };
