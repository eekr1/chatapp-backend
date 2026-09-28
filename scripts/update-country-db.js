const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const packageEntry = require.resolve('ip-location-api');
const packageRoot = path.resolve(path.dirname(packageEntry), '..');
const updater = path.join(packageRoot, 'script', 'updatedb.cjs');
const result = spawnSync(process.execPath, [updater], {
    cwd: path.resolve(__dirname, '..'),
    env: {
        ...process.env,
        ILA_FIELDS: 'country',
        ILA_IP_LOCATION_DB: 'user',
        ILA_DATA_DIR: path.resolve(__dirname, '..', 'data', 'ip-country'),
        ILA_TMP_DATA_DIR: path.join(os.tmpdir(), 'talkx-ip-country-update'),
        ILA_DOWNLOAD_TYPE: 'false',
        ILA_AUTO_UPDATE: 'false'
    },
    stdio: 'inherit'
});

if (result.error) throw result.error;
process.exitCode = result.status || 0;
