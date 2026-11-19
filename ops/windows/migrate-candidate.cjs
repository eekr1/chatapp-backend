'use strict';
const fs = require('node:fs'), path = require('node:path');
const { spawnSync } = require('node:child_process');
const cwd = process.argv[2];
if (!/^C:[\\/]TalkX[\\/]releases[\\/][a-f0-9]{40}$/i.test(cwd || '')) {
  process.stderr.write('Invalid release directory\n');
  process.exit(1);
}
try {
  Object.assign(process.env, require(path.join(cwd, 'node_modules/dotenv')).parse(fs.readFileSync('C:/TalkX/secrets/backend.env')));
  const res = spawnSync(process.execPath, [path.join(cwd, 'scripts/migrate.js')], {
    cwd,
    env: process.env,
    windowsHide: true,
    stdio: 'ignore'
  });
  if (res.error || res.status !== 0) {
    process.stderr.write('Migration failed\n');
    process.exitCode = 1;
  }
} catch {
  process.stderr.write('Migration setup failed\n');
  process.exitCode = 1;
}
