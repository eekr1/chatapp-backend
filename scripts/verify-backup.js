const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const sha256File = (filePath) => new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
});

const verifyBackup = async ({ filePath, expectedSha256, restoreBin = process.env.PG_RESTORE_BIN || 'pg_restore' }) => {
    const resolvedPath = path.resolve(filePath);
    const stat = await fs.promises.stat(resolvedPath);
    if (!stat.isFile()) throw Object.assign(new Error('Backup path is not a file.'), { code: 'BACKUP_NOT_FILE' });
    const sha256 = await sha256File(resolvedPath);
    if (expectedSha256 && sha256.toLowerCase() !== String(expectedSha256).trim().toLowerCase()) {
        throw Object.assign(new Error('Backup checksum does not match.'), { code: 'BACKUP_CHECKSUM_MISMATCH' });
    }

    const listed = spawnSync(restoreBin, ['--list', resolvedPath], { encoding: 'utf8', windowsHide: true });
    if (listed.error || listed.status !== 0) {
        throw Object.assign(new Error('pg_restore could not list the archive.'), { code: 'BACKUP_ARCHIVE_INVALID' });
    }
    const entries = String(listed.stdout || '').split(/\r?\n/).filter((line) => /^\d+;/.test(line.trim()));
    return { file: resolvedPath, bytes: stat.size, sha256, archiveEntries: entries.length };
};

if (require.main === module) {
    const filePath = process.argv[2];
    const expectedSha256 = process.argv[3] || '';
    if (!filePath) {
        console.error('Usage: npm run backup:verify -- <dump-path> [expected-sha256]');
        process.exitCode = 2;
    } else {
        verifyBackup({ filePath, expectedSha256 })
            .then((result) => console.log(JSON.stringify(result)))
            .catch((error) => {
                console.error(JSON.stringify({ status: 'failed', errorCode: error?.code || 'BACKUP_VERIFY_FAILED' }));
                process.exitCode = 1;
            });
    }
}

module.exports = { sha256File, verifyBackup };
