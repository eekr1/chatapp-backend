const crypto = require('crypto');

const POLICY_VERSION = 'talkx-data-policy-v1';
const OPEN_STATES = new Set(['requested', 'reviewing', 'approved', 'processing', 'failed_retryable']);
const PRE_PROCESSING_STATES = new Set(['requested', 'reviewing', 'approved']);

const canRejectDeletion = (status) => PRE_PROCESSING_STATES.has(String(status || ''));
const buildSubjectRef = ({ userId, hmacKey, keyVersion = 'v1' }) => {
    if (!hmacKey || String(hmacKey).length < 32) {
        throw Object.assign(new Error('Erasure HMAC key is unavailable.'), { code: 'ERASURE_KEY_UNAVAILABLE' });
    }
    return `${keyVersion}:${crypto.createHmac('sha256', hmacKey).update(String(userId)).digest('hex')}`;
};
const checksumSteps = (steps) => crypto.createHash('sha256').update(JSON.stringify(steps)).digest('hex');

const executeAccountDeletion = async ({ pool, requestId, actorAdmin, note = null, hmacKey, keyVersion = 'v1' }) => {
    const db = await pool.connect();
    try {
        await db.query('BEGIN');
        const selected = await db.query(
            `SELECT id, user_id, status, policy_version, receipt
             FROM account_deletion_requests WHERE id = $1 FOR UPDATE`,
            [requestId]
        );
        if (!selected.rows.length) throw Object.assign(new Error('Deletion request not found.'), { code: 'DELETION_NOT_FOUND' });
        const request = selected.rows[0];
        if (request.status === 'completed') {
            await db.query('COMMIT');
            return { idempotent: true, receipt: request.receipt };
        }
        if (!OPEN_STATES.has(request.status) || !request.user_id) {
            throw Object.assign(new Error('Deletion request cannot be processed.'), { code: 'DELETION_STATE_INVALID' });
        }
        const subjectRef = buildSubjectRef({ userId: request.user_id, hmacKey, keyVersion });
        await db.query(
            `UPDATE account_deletion_requests
             SET status = 'processing', processing_started_at = COALESCE(processing_started_at, NOW()), failure_code = NULL
             WHERE id = $1`, [requestId]
        );

        const steps = [];
        const runStep = async (stepKey, sql, params = [request.user_id]) => {
            await db.query(
                `INSERT INTO account_deletion_steps(request_id, step_key, status, started_at)
                 VALUES($1, $2, 'processing', NOW())
                 ON CONFLICT(request_id, step_key) DO UPDATE SET status='processing', started_at=COALESCE(account_deletion_steps.started_at, NOW()), updated_at=NOW()`,
                [requestId, stepKey]
            );
            const result = await db.query(sql, params);
            const affected = Number(result.rowCount) || 0;
            await db.query(
                `UPDATE account_deletion_steps SET status='completed', affected_count=$3, completed_at=NOW(), updated_at=NOW()
                 WHERE request_id=$1 AND step_key=$2`, [requestId, stepKey, affected]
            );
            steps.push({ stepKey, affected });
        };

        await runStep('runtime_leases', 'DELETE FROM connection_leases WHERE user_id = $1');
        await runStep('sessions', 'DELETE FROM sessions WHERE user_id = $1');
        await runStep('country', 'DELETE FROM user_match_country WHERE user_id = $1');
        await runStep('push_devices', 'DELETE FROM push_devices WHERE user_id = $1');
        await runStep('relationships', 'DELETE FROM friendships WHERE user_id = $1 OR friend_user_id = $1');
        await runStep('blocks', 'DELETE FROM blocks WHERE blocker_id = $1 OR blocked_id = $1');
        await runStep('media', 'DELETE FROM ephemeral_media WHERE sender_id = $1 OR receiver_id = $1');
        await runStep('messages', 'UPDATE messages SET sender_id = NULL WHERE sender_id = $1');
        await runStep('conversations', 'UPDATE conversations SET user_a_id = NULL WHERE user_a_id = $1');
        await runStep('conversations_peer', 'UPDATE conversations SET user_b_id = NULL WHERE user_b_id = $1');
        await runStep('reports_reporter', `UPDATE reports SET reporter_user_id=NULL, meta=COALESCE(meta, '{}'::jsonb) - 'username' - 'email' - 'ip' - 'device_id' WHERE reporter_user_id=$1`);
        await runStep('reports_subject', `UPDATE reports SET reported_user_id=NULL, meta=COALESCE(meta, '{}'::jsonb) - 'username' - 'email' - 'ip' - 'device_id' WHERE reported_user_id=$1`);
        await runStep('bans', 'UPDATE bans SET user_id=NULL WHERE user_id=$1');
        await runStep('support_media', 'DELETE FROM support_report_media WHERE report_id IN (SELECT id FROM support_reports WHERE user_id=$1)');
        await runStep('support', `UPDATE support_reports SET user_id=NULL, username_snapshot=NULL, contact_email=NULL, ip=NULL, user_agent=NULL, device_model=NULL, network_type=NULL, last_error_code=NULL, description='[removed by account deletion]', updated_at=NOW() WHERE user_id=$1`);
        await runStep('push_logs', `UPDATE push_delivery_logs SET target_user_id=NULL, meta='{}'::jsonb WHERE target_user_id=$1`);
        await runStep('behavior', `UPDATE behavior_events SET user_id=NULL, client_id=NULL, device_id=NULL, metadata='{}'::jsonb WHERE user_id=$1`);
        await runStep('user', 'DELETE FROM users WHERE id = $1');

        const orphanCheck = await db.query(`
            SELECT
              (SELECT COUNT(*) FROM users WHERE id=$1) +
              (SELECT COUNT(*) FROM sessions WHERE user_id=$1) +
              (SELECT COUNT(*) FROM connection_leases WHERE user_id=$1) +
              (SELECT COUNT(*) FROM user_match_country WHERE user_id=$1) +
              (SELECT COUNT(*) FROM push_devices WHERE user_id=$1) +
              (SELECT COUNT(*) FROM friendships WHERE user_id=$1 OR friend_user_id=$1) +
              (SELECT COUNT(*) FROM blocks WHERE blocker_id=$1 OR blocked_id=$1) +
              (SELECT COUNT(*) FROM ephemeral_media WHERE sender_id=$1 OR receiver_id=$1) +
              (SELECT COUNT(*) FROM reports WHERE reporter_user_id=$1 OR reported_user_id=$1) +
              (SELECT COUNT(*) FROM bans WHERE user_id=$1) +
              (SELECT COUNT(*) FROM support_reports WHERE user_id=$1) +
              (SELECT COUNT(*) FROM push_delivery_logs WHERE target_user_id=$1) +
              (SELECT COUNT(*) FROM behavior_events WHERE user_id=$1) AS remaining
        `, [request.user_id]);
        const remaining = Number(orphanCheck.rows?.[0]?.remaining) || 0;
        if (remaining !== 0) {
            throw Object.assign(new Error('Deletion orphan verification failed.'), { code: 'DELETION_ORPHANS_REMAIN', remaining });
        }
        await db.query(
            `INSERT INTO account_deletion_steps(request_id, step_key, status, affected_count, result, started_at, completed_at)
             VALUES($1, 'orphan_verification', 'completed', 0, $2::jsonb, NOW(), NOW())
             ON CONFLICT(request_id, step_key) DO UPDATE SET status='completed', result=EXCLUDED.result, completed_at=NOW(), updated_at=NOW()`,
            [requestId, JSON.stringify({ remaining: 0 })]
        );
        steps.push({ stepKey: 'orphan_verification', affected: 0 });
        await db.query(
            `INSERT INTO account_deletion_steps(request_id, step_key, status, affected_count, result, started_at, completed_at)
             VALUES($1, 'external_processors', 'completed', 0, $2::jsonb, NOW(), NOW())
             ON CONFLICT(request_id, step_key) DO UPDATE SET status='completed', result=EXCLUDED.result, completed_at=NOW(), updated_at=NOW()`,
            [requestId, JSON.stringify({ limitations: ['previously delivered support email and push are subject to processor retention terms'], ownerReview: 'checkpoint_required' })]
        );
        steps.push({ stepKey: 'external_processors', affected: 0 });

        const stepChecksum = checksumSteps(steps);
        const receipt = { requestId, status: 'completed', policyVersion: request.policy_version || POLICY_VERSION, subjectRef, stepChecksum };
        await db.query(
            `INSERT INTO erasure_journal(request_id, subject_ref, key_version, policy_version, step_checksum, completed_at)
             VALUES($1,$2,$3,$4,$5,NOW()) ON CONFLICT(request_id) DO NOTHING`,
            [requestId, subjectRef, keyVersion, receipt.policyVersion, stepChecksum]
        );
        await db.query(
            `UPDATE account_deletion_requests
             SET user_id=NULL, username_snapshot=$2, status='completed', completed_at=NOW(), reviewed_at=NOW(), reviewed_by=$3,
                 note=$4, receipt=$5::jsonb, failure_code=NULL
             WHERE id=$1`,
            [requestId, subjectRef, actorAdmin, note, JSON.stringify(receipt)]
        );
        await db.query(
            `INSERT INTO admin_action_audit(actor_admin, action_type, entity_type, entity_id, payload)
             VALUES($1, 'DELETION_COMPLETE', 'account_deletion_request', $2, $3::jsonb)`,
            [actorAdmin, requestId, JSON.stringify({ requestRef: requestId, policyVersion: receipt.policyVersion, stepChecksum })]
        );
        await db.query('COMMIT');
        return { idempotent: false, receipt, steps };
    } catch (error) {
        try { await db.query('ROLLBACK'); } catch { /* best effort */ }
        if (!['DELETION_NOT_FOUND', 'DELETION_STATE_INVALID'].includes(error?.code)) {
            try {
                await pool.query(
                    `UPDATE account_deletion_requests
                     SET status='failed_retryable', failure_code=$2
                     WHERE id=$1 AND status IN ('approved','processing','failed_retryable')`,
                    [requestId, String(error?.code || 'DELETION_STEP_FAILED').slice(0, 120)]
                );
            } catch { /* preserve original failure */ }
        }
        throw error;
    } finally {
        db.release();
    }
};

module.exports = { POLICY_VERSION, OPEN_STATES, canRejectDeletion, buildSubjectRef, executeAccountDeletion };
