const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
    FORMAT, ALGORITHM, RETENTION_DAYS,
    parseBackendEnv, parseDatabaseUrl, libpqEnv, redact, decodeKey,
    encryptDump, decryptDump, selectExpiredBackups, keyNameForBackup
} = require('../ops/windows/backup.cjs');

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

test('backend.env fallback parser handles comments, quotes and blank lines', () => {
    assert.deepEqual(parseBackendEnv('A=1\r\n# comment\nB="two words"\n\nC=\'quoted\'\n='), { A: '1', B: 'two words', C: 'quoted' });
    assert.deepEqual(parseBackendEnv(''), {});
    assert.deepEqual(parseBackendEnv(null), {});
});

test('DATABASE_URL is parsed with percent-decoded credentials and defaults', () => {
    const conn = parseDatabaseUrl('postgresql://user:p%40ss%23word@db.example.com:5432/chat?sslmode=require&channel_binding=require');
    assert.equal(conn.host, 'db.example.com');
    assert.equal(conn.port, '5432');
    assert.equal(conn.user, 'user');
    assert.equal(conn.password, 'p@ss#word');
    assert.equal(conn.database, 'chat');
    assert.equal(conn.params.sslmode, 'require');
    const minimal = parseDatabaseUrl('postgres://u:k@host/db');
    assert.equal(minimal.port, '5432');
    assert.throws(() => parseDatabaseUrl('mysql://u:k@host/db'), /PostgreSQL/);
});

test('credentials map to libpq environment variables only, never argv', () => {
    const env = libpqEnv(parseDatabaseUrl('postgresql://user:p@ssword@db.example.com:5432/chat?sslmode=require&unknown=1'));
    assert.equal(env.PGHOST, 'db.example.com');
    assert.equal(env.PGUSER, 'user');
    assert.equal(env.PGPASSWORD, 'p@ssword');
    assert.equal(env.PGDATABASE, 'chat');
    assert.equal(env.PGSSLMODE, 'require');
    assert.equal(env.unknown, undefined);
});

test('redact removes every credential occurrence from tool output', () => {
    const out = redact('pg_dump: connection to server failed for user "u" passsword=abc123 ok', ['abc123']);
    assert.equal(out.includes('abc123'), false);
    assert.equal(out.includes('***'), true);
    assert.equal(redact(null, ['x']), '');
});

test('key decoding accepts 32-byte buffers, base64 and hex text, rejects wrong sizes', () => {
    const key = crypto.randomBytes(32);
    assert.deepEqual(decodeKey(key), key);
    assert.deepEqual(decodeKey(key.toString('base64') + '\n'), key);
    assert.deepEqual(decodeKey(key.toString('hex')), key);
    assert.deepEqual(decodeKey(key), decodeKey(decodeKey(key.toString('base64'))));
    assert.throws(() => decodeKey(crypto.randomBytes(16)), /32 bytes/);
    assert.throws(() => decodeKey('not-a-key'), /32 bytes/);
});

test('encrypt/decrypt roundtrip restores the dump and fails on wrong key or tampering', () => {
    const key = crypto.randomBytes(32);
    const dump = Buffer.concat([Buffer.from('PGDMP'), crypto.randomBytes(1024)]);
    const envelope = encryptDump(dump, key);
    assert.equal(envelope.format, FORMAT);
    assert.equal(envelope.algorithm, ALGORITHM);
    assert.equal(envelope.sha256, crypto.createHash('sha256').update(dump).digest('hex'));
    assert.equal(envelope.bytes, dump.length);
    assert.equal(Buffer.from(envelope.iv, 'base64').length, 12);
    assert.equal(Buffer.from(envelope.authTag, 'base64').length, 16);
    assert.equal(envelope.data.includes(dump.toString('hex').slice(0, 20)), false);
    assert.deepEqual(decryptDump(envelope, key), dump);
    assert.throws(() => decryptDump(envelope, crypto.randomBytes(32)), Error);
    const tampered = { ...envelope, data: Buffer.from('tampered').toString('base64') };
    assert.throws(() => decryptDump(tampered, key), Error);
    assert.throws(() => decryptDump({ ...envelope, format: 'other' }, key), /envelope/);
});

test('retention keeps backups newer than 14 days and selects older ones', () => {
    const now = Date.parse('2026-11-19T03:00:00Z');
    const entries = [
        { name: 'old.dump.aes.json', mtimeMs: now - 15 * DAY },
        { name: 'boundary.dump.aes.json', mtimeMs: now - RETENTION_DAYS * DAY },
        { name: 'fresh.dump.aes.json', mtimeMs: now - 13 * DAY - 23 * HOUR }
    ];
    assert.deepEqual(selectExpiredBackups(entries, now), ['old.dump.aes.json']);
    assert.equal(selectExpiredBackups([], now).length, 0);
    assert.deepEqual(selectExpiredBackups([{ name: 'x', mtimeMs: undefined }], now), []);
});

test('backup file names map to their paired key file names', () => {
    assert.equal(keyNameForBackup('talkx-db-20261119T040000Z.dump.aes.json'), 'backup-20261119T040000Z.key');
    assert.equal(keyNameForBackup('talkx-db-20261119T040000Z.dump.aes.json.bak'), null);
    assert.equal(keyNameForBackup('unrelated.json'), null);
    assert.equal(keyNameForBackup(''), null);
});