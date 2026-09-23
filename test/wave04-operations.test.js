const test = require('node:test');
const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const path = require('node:path');

const { createMigrationRunner, checksumMigration, validateMigrations } = require('../migrations/runner');
const { createHealthState, createLivenessPayload, createReadinessPayload } = require('../utils/health');
const { resolveDatabaseRuntimeConfig, resolveReleaseIdentity } = require('../utils/runtimeConfig');
const { buildPerformanceOverview, buildRouteImpact } = require('../utils/performanceContract');

const createFakeMigrationPool = ({ failSql = null, initialRows = [] } = {}) => {
    const calls = [];
    const rows = new Map(initialRows.map((row) => [row.version, { ...row }]));
    const client = {
        async query(sql, params = []) {
            const text = typeof sql === 'string' ? sql : sql.text;
            calls.push([text, params]);
            if (text.trim() === failSql) throw Object.assign(new Error('fixture failure'), { code: 'FIXTURE_FAILURE' });
            if (/SELECT version, checksum, result FROM schema_migrations/.test(text)) {
                return { rows: [...rows.values()].map(({ version, checksum, result }) => ({ version, checksum, result })) };
            }
            if (/SELECT version, name, checksum, applied_at/.test(text)) return { rows: [...rows.values()] };
            if (/INSERT INTO schema_migrations/.test(text)) {
                const failed = text.includes("'failed'");
                rows.set(params[0], {
                    version: params[0], name: params[1], checksum: params[2], applied_at: new Date(),
                    duration_ms: params[3], result: failed ? 'failed' : 'applied', error_code: failed ? params[4] : null
                });
            }
            return { rows: [] };
        },
        release() { calls.push(['RELEASE', []]); }
    };
    return { pool: { connect: async () => client }, calls, rows };
};

test('runtime config clamps DB limits and release identity is allowlisted', () => {
    const config = resolveDatabaseRuntimeConfig({ NODE_ENV: 'production', DB_POOL_MAX: '999', DB_QUERY_TIMEOUT_MS: '-1' });
    assert.equal(config.max, 20);
    assert.equal(config.query_timeout, 500);
    assert.deepEqual(resolveReleaseIdentity({ APP_ENV: 'preview', COMMIT_SHA: 'not-a-sha' }), {
        service: 'talkx-backend', appVersion: '1.0.0', commitSha: 'unknown', environment: 'unknown'
    });
    assert.equal(resolveReleaseIdentity({ NODE_ENV: 'staging', COMMIT_SHA: 'abcdef1234567' }).commitSha, 'abcdef1234567');
});

test('liveness is DB-independent and readiness fails closed without leaking an error', () => {
    const release = resolveReleaseIdentity({ NODE_ENV: 'test', COMMIT_SHA: 'abcdef1' });
    const healthState = createHealthState();
    const now = () => new Date('2026-09-23T00:00:00.000Z');
    assert.equal(createLivenessPayload({ release, healthState, now }).status, 'live');
    const payload = createReadinessPayload({
        release,
        healthState,
        database: { ok: false, code: 'DB_TIMEOUT', schema: 'unknown', expectedMigrationHead: '001' },
        now
    });
    assert.equal(payload.status, 'not_ready');
    assert.equal(payload.checks.database.code, 'DB_TIMEOUT');
    assert.equal(JSON.stringify(payload).includes('postgres://'), false);
    healthState.shuttingDown = true;
    assert.equal(createLivenessPayload({ release, healthState, now }).status, 'shutting_down');
});

test('migration runner applies once under advisory lock and then is idempotent', async () => {
    const migration = { version: '001', name: 'initial', sql: 'CREATE TABLE example(id int)' };
    const fake = createFakeMigrationPool();
    const runner = createMigrationRunner({ pool: fake.pool, migrations: [migration], lockId: 42 });
    const first = await runner.run();
    const second = await runner.run();
    assert.equal(first.ok, true);
    assert.equal(second.currentHead, '001');
    assert.equal(fake.calls.filter(([sql]) => sql === migration.sql).length, 1);
    assert.equal(fake.calls.filter(([sql]) => sql === 'SELECT pg_advisory_lock($1)').length, 2);
    assert.equal(fake.calls.filter(([sql]) => sql === 'SELECT pg_advisory_unlock($1)').length, 2);
});

test('migration failure rolls back, remains visible and checksum drift blocks startup', async () => {
    const migration = { version: '001', name: 'broken', sql: 'BROKEN' };
    const fake = createFakeMigrationPool({ failSql: 'BROKEN' });
    const runner = createMigrationRunner({ pool: fake.pool, migrations: [migration] });
    await assert.rejects(runner.run(), (error) => error.code === 'MIGRATION_FAILED' && error.version === '001');
    assert.equal(fake.rows.get('001').result, 'failed');
    assert.ok(fake.calls.some(([sql]) => sql === 'ROLLBACK'));

    const drift = createFakeMigrationPool({
        initialRows: [{ version: '001', checksum: 'different', result: 'applied' }]
    });
    const driftRunner = createMigrationRunner({ pool: drift.pool, migrations: [migration] });
    await assert.rejects(driftRunner.run(), (error) => error.code === 'MIGRATION_CHECKSUM_MISMATCH');
});

test('migration manifest and checksum are deterministic', () => {
    const migration = { version: '001', name: 'initial', sql: 'SELECT 1' };
    assert.equal(checksumMigration(migration), checksumMigration({ ...migration }));
    assert.equal(validateMigrations([migration])[0].checksum.length, 64);
    assert.throws(() => validateMigrations([
        migration,
        { version: '001', name: 'duplicate', sql: 'SELECT 2' }
    ]), (error) => error.code === 'MIGRATION_MANIFEST_INVALID');
    assert.throws(() => validateMigrations([
        migration,
        { version: '003', name: 'gap', sql: 'SELECT 3' }
    ]), (error) => error.code === 'MIGRATION_MANIFEST_INVALID');
});

test('performance contract distinguishes no data and low confidence from healthy zero', () => {
    const noData = buildPerformanceOverview({ hours: 24, totals: {}, previousTotals: {}, percentiles: {} });
    assert.equal(noData.data_state, 'no_data');
    assert.equal(noData.p95_ms, null);
    assert.equal(noData.error_rate, null);

    const low = buildPerformanceOverview({
        hours: 1,
        totals: { total_requests: 12, error_requests: 0, total_duration_ms: 0, last_bucket_at: new Date() },
        previousTotals: {},
        percentiles: { sample_count: 2, p50_ms: 0, p95_ms: 0, p99_ms: 0 }
    });
    assert.equal(low.confidence, 'low');
    assert.equal(low.evaluation, 'low_confidence');
    assert.equal(low.p95_ms, null);
    assert.equal(low.error_rate, 0);
});

test('route impact combines traffic, errors and latency deterministically', () => {
    const impact = buildRouteImpact(
        [
            { method: 'GET', route: '/slow', sample_count: 30, p95_ms: 2000 },
            { method: 'GET', route: '/sampled-only', sample_count: 10, p95_ms: 3000 }
        ],
        [
            { method: 'GET', route: '/busy', req_count: 1000, error_count: 2, error_rate: 0.2 },
            { method: 'GET', route: '/slow', req_count: 5, error_count: 1, error_rate: 20 }
        ]
    );
    assert.equal(impact[0].key, 'GET /busy');
    assert.ok(impact.every((row) => Number.isFinite(row.impact_score)));
    assert.equal(impact.find((row) => row.key === 'GET /sampled-only').impact_score, 30000);
});

test('performance thresholds, stale and partial states are deterministic', () => {
    const now = new Date('2026-09-23T12:00:00.000Z');
    const base = {
        hours: 1,
        totals: {
            total_requests: 100,
            error_requests: 5,
            total_duration_ms: 50000,
            last_bucket_at: '2026-09-23T11:30:00.000Z'
        },
        previousTotals: { total_requests: 80, error_requests: 1 },
        percentiles: { sample_count: 20, p50_ms: 400, p95_ms: 1500, p99_ms: 2000 },
        now
    };
    const staleCritical = buildPerformanceOverview(base);
    assert.equal(staleCritical.data_state, 'stale');
    assert.equal(staleCritical.evaluation, 'critical');
    assert.equal(staleCritical.previous_period.error_rate, 1.25);
    const partial = buildPerformanceOverview({ ...base, partial: true });
    assert.equal(partial.data_state, 'partial');
});

test('health and operation surfaces do not expose raw database configuration', async () => {
    const [indexSource, deployRunbook, restoreRunbook] = await Promise.all([
        readFile(path.resolve(__dirname, '../index.js'), 'utf8'),
        readFile(path.resolve(__dirname, '../docs/WAVE04_DEPLOY_RUNBOOK.md'), 'utf8'),
        readFile(path.resolve(__dirname, '../docs/WAVE04_BACKUP_RESTORE_RUNBOOK.md'), 'utf8')
    ]);
    assert.match(indexSource, /\/health\/live/);
    assert.match(indexSource, /\/health\/ready/);
    assert.doesNotMatch(`${deployRunbook}\n${restoreRunbook}`, /postgres(?:ql)?:\/\/[^\s]+/i);
    assert.match(deployRunbook, /chatapp-frontend\/android/);
    assert.match(restoreRunbook, /explicit approval/i);
});

test('admin performance UI renders no-data and route impact explicitly', async () => {
    const source = await readFile(path.resolve(__dirname, '../admin.html'), 'utf8');
    assert.match(source, /x\.p95_ms==null\?'Veri yok'/);
    assert.match(source, /Route Etki Sirasi/);
    assert.match(source, /Release Health ayrı metriklerdir/);
});
