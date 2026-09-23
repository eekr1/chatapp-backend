const crypto = require('crypto');

const DEFAULT_LOCK_ID = 74004001;
const LEDGER_SQL = `
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        checksum TEXT NOT NULL,
        applied_at TIMESTAMPTZ,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        result TEXT NOT NULL CHECK (result IN ('applied', 'failed')),
        error_code TEXT
    )
`;

const checksumMigration = ({ version, name, sql }) => crypto
    .createHash('sha256')
    .update(`${version}\0${name}\0${sql}`)
    .digest('hex');

const validateMigrations = (migrations = []) => {
    if (!Array.isArray(migrations) || migrations.length === 0) {
        throw Object.assign(new Error('Migration manifest is empty.'), { code: 'MIGRATION_MANIFEST_EMPTY' });
    }
    let previous = null;
    let previousNumber = null;
    const seen = new Set();
    return migrations.map((migration) => {
        const version = String(migration?.version || '').trim();
        const name = String(migration?.name || '').trim();
        const sql = String(migration?.sql || '').trim();
        const versionNumber = Number(version);
        const hasGap = previousNumber !== null && versionNumber !== previousNumber + 1;
        if (!/^\d{3,}$/.test(version) || !name || !sql || seen.has(version) || (previous && version <= previous) || hasGap) {
            throw Object.assign(new Error('Migration manifest is invalid.'), { code: 'MIGRATION_MANIFEST_INVALID' });
        }
        seen.add(version);
        previous = version;
        previousNumber = versionNumber;
        return Object.freeze({ version, name, sql, checksum: checksumMigration({ version, name, sql }) });
    });
};

const inspectMigrationState = async (queryable, migrations) => {
    const manifest = validateMigrations(migrations);
    const result = await queryable.query(
        `SELECT version, name, checksum, applied_at, duration_ms, result, error_code
         FROM schema_migrations
         ORDER BY version ASC`
    );
    const rows = result.rows || [];
    const byVersion = new Map(rows.map((row) => [String(row.version), row]));
    const mismatches = manifest.filter((migration) => {
        const row = byVersion.get(migration.version);
        return row && row.checksum !== migration.checksum;
    });
    const failed = rows.filter((row) => row.result !== 'applied');
    const pending = manifest.filter((migration) => byVersion.get(migration.version)?.result !== 'applied');
    const manifestVersions = new Set(manifest.map((migration) => migration.version));
    const unexpected = rows.filter((row) => !manifestVersions.has(String(row.version)));
    return {
        ok: mismatches.length === 0 && failed.length === 0 && pending.length === 0 && unexpected.length === 0,
        expectedHead: manifest.at(-1).version,
        currentHead: rows.filter((row) => row.result === 'applied').at(-1)?.version || null,
        pending: pending.map((item) => item.version),
        failed: failed.map((item) => String(item.version)),
        checksumMismatch: mismatches.map((item) => item.version),
        unexpected: unexpected.map((item) => String(item.version))
    };
};

const createMigrationRunner = ({ pool, migrations, lockId = DEFAULT_LOCK_ID }) => {
    const manifest = validateMigrations(migrations);

    const run = async () => {
        const client = await pool.connect();
        let locked = false;
        try {
            await client.query('SELECT pg_advisory_lock($1)', [lockId]);
            locked = true;
            await client.query(LEDGER_SQL);
            const existing = await client.query(
                'SELECT version, checksum, result FROM schema_migrations ORDER BY version ASC'
            );
            const byVersion = new Map((existing.rows || []).map((row) => [String(row.version), row]));

            for (const migration of manifest) {
                const recorded = byVersion.get(migration.version);
                if (recorded?.checksum && recorded.checksum !== migration.checksum) {
                    throw Object.assign(new Error('Applied migration checksum mismatch.'), {
                        code: 'MIGRATION_CHECKSUM_MISMATCH', version: migration.version
                    });
                }
                if (recorded?.result === 'applied') continue;

                const startedAt = Date.now();
                try {
                    await client.query('BEGIN');
                    await client.query(migration.sql);
                    await client.query(
                        `INSERT INTO schema_migrations
                            (version, name, checksum, applied_at, duration_ms, result, error_code)
                         VALUES ($1, $2, $3, NOW(), $4, 'applied', NULL)
                         ON CONFLICT (version) DO UPDATE SET
                            name = EXCLUDED.name,
                            checksum = EXCLUDED.checksum,
                            applied_at = EXCLUDED.applied_at,
                            duration_ms = EXCLUDED.duration_ms,
                            result = 'applied',
                            error_code = NULL`,
                        [migration.version, migration.name, migration.checksum, Date.now() - startedAt]
                    );
                    await client.query('COMMIT');
                } catch (error) {
                    await client.query('ROLLBACK').catch(() => {});
                    await client.query(
                        `INSERT INTO schema_migrations
                            (version, name, checksum, applied_at, duration_ms, result, error_code)
                         VALUES ($1, $2, $3, NOW(), $4, 'failed', $5)
                         ON CONFLICT (version) DO UPDATE SET
                            applied_at = EXCLUDED.applied_at,
                            duration_ms = EXCLUDED.duration_ms,
                            result = 'failed',
                            error_code = EXCLUDED.error_code`,
                        [migration.version, migration.name, migration.checksum, Date.now() - startedAt, 'MIGRATION_FAILED']
                    );
                    throw Object.assign(new Error('Migration failed.'), {
                        code: 'MIGRATION_FAILED', version: migration.version, cause: error
                    });
                }
            }
            return inspectMigrationState(client, manifest);
        } finally {
            if (locked) await client.query('SELECT pg_advisory_unlock($1)', [lockId]).catch(() => {});
            client.release();
        }
    };

    return {
        expectedHead: manifest.at(-1).version,
        inspect: (queryable) => inspectMigrationState(queryable, manifest),
        migrations: manifest,
        run
    };
};

module.exports = {
    DEFAULT_LOCK_ID,
    LEDGER_SQL,
    checksumMigration,
    validateMigrations,
    inspectMigrationState,
    createMigrationRunner
};
