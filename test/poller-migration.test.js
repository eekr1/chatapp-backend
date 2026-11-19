const test = require('node:test');
const assert = require('node:assert/strict');

const { interpretReadiness, classifyCandidate } = require('../ops/windows/poller.cjs');

// --- interpretReadiness ---

test('interpretReadiness: 200 OK is ready', () => {
    const result = interpretReadiness(200, { commitSha: 'abc', database: { ok: true } });
    assert.deepEqual(result, { ok: true, reason: 'ready' });
});

test('interpretReadiness: 503 with MIGRATION_NOT_CURRENT and DB ahead is acceptable', () => {
    const result = interpretReadiness(503, {
        database: {
            code: 'MIGRATION_NOT_CURRENT',
            migrationHead: '011',
            expectedMigrationHead: '010'
        }
    });
    assert.deepEqual(result, { ok: true, reason: 'migration_ahead' });
});

test('interpretReadiness: 503 with MIGRATION_NOT_CURRENT and DB ahead via checks.database payload is acceptable', () => {
    const result = interpretReadiness(503, {
        checks: {
            database: {
                code: 'MIGRATION_NOT_CURRENT',
                migrationHead: '011',
                expectedMigrationHead: '010'
            }
        }
    });
    assert.deepEqual(result, { ok: true, reason: 'migration_ahead' });
});

test('interpretReadiness: 503 with MIGRATION_NOT_CURRENT and DB behind is NOT acceptable', () => {
    const result = interpretReadiness(503, {
        database: {
            code: 'MIGRATION_NOT_CURRENT',
            migrationHead: '009',
            expectedMigrationHead: '010'
        }
    });
    assert.deepEqual(result, { ok: false, reason: 'MIGRATION_NOT_CURRENT' });
});

test('interpretReadiness: 503 with MIGRATION_NOT_CURRENT and equal heads is NOT acceptable', () => {
    const result = interpretReadiness(503, {
        database: {
            code: 'MIGRATION_NOT_CURRENT',
            migrationHead: '010',
            expectedMigrationHead: '010'
        }
    });
    assert.deepEqual(result, { ok: false, reason: 'MIGRATION_NOT_CURRENT' });
});

test('interpretReadiness: 503 with other database error is not acceptable', () => {
    const result = interpretReadiness(503, {
        database: { code: 'CONNECTION_FAILED' }
    });
    assert.deepEqual(result, { ok: false, reason: 'CONNECTION_FAILED' });
});

test('interpretReadiness: 503 with no database field returns not_ready', () => {
    const result = interpretReadiness(503, { error: 'something' });
    assert.deepEqual(result, { ok: false, reason: 'not_ready' });
});

test('interpretReadiness: any 2xx is ready', () => {
    for (const status of [200, 201, 204, 299]) {
        const result = interpretReadiness(status, {});
        assert.equal(result.ok, true, `status ${status} should be ok`);
        assert.equal(result.reason, 'ready');
    }
});

test('interpretReadiness: missing migrationHead fields rejects', () => {
    const result = interpretReadiness(503, {
        database: { code: 'MIGRATION_NOT_CURRENT', migrationHead: '011' }
    });
    assert.equal(result.ok, false);
});

// --- classifyCandidate ---

test('classifyCandidate: no directory means fresh', () => {
    const result = classifyCandidate(false, false, false);
    assert.deepEqual(result, { action: 'fresh', reason: 'no_candidate' });
});

test('classifyCandidate: directory with .candidate-failed flag aborts', () => {
    const result = classifyCandidate(true, true, true);
    assert.deepEqual(result, { action: 'abort', reason: 'candidate_failed_flag' });
});

test('classifyCandidate: directory without flag and correct HEAD resumes', () => {
    const result = classifyCandidate(true, false, true);
    assert.deepEqual(result, { action: 'resume', reason: 'resuming_candidate' });
});

test('classifyCandidate: directory without flag but wrong HEAD aborts', () => {
    const result = classifyCandidate(true, false, false);
    assert.deepEqual(result, { action: 'abort', reason: 'head_mismatch' });
});

test('classifyCandidate: failed flag takes priority over head mismatch', () => {
    const result = classifyCandidate(true, true, false);
    assert.equal(result.action, 'abort');
    assert.equal(result.reason, 'candidate_failed_flag');
});
