import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const testDir = path.join(repoRoot, 'test');
const coreTests = [
  'wave01-security.test.js',
  'wave02-platform.test.js',
  'wave04-operations.test.js',
  'wave05-recovery-presence.test.js',
  'wave06-data-lifecycle.test.js',
  'wave07-search-lifecycle.test.js',
  'wave08-match-scope.test.js',
  'wave09-pending-match.test.js',
  'wave10-direct-message.test.js',
  'wave11-media-trust.test.js',
  'wave12-legal-account.test.js',
  'wave13-locale-notification.test.js',
  'wave14-sale-overview.test.js',
  'wave15-admin-operations.test.js'
];
const criticalTests = [
  'wave02-platform.test.js',
  'wave05-recovery-presence.test.js',
  'wave07-search-lifecycle.test.js',
  'wave08-match-scope.test.js',
  'wave09-pending-match.test.js',
  'wave10-direct-message.test.js',
  'wave12-legal-account.test.js'
];
const blockedExternalVariables = [
  'DATABASE_URL',
  'FIREBASE_SERVICE_ACCOUNT',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'BREVO_API_KEY'
];
const excludedDirectories = new Set(['.git', 'node_modules', 'Plans', 'docs']);

const fail = (message) => {
  throw new Error(`[quality-gate] ${message}`);
};

const assertNoExternalTargets = (env = process.env) => {
  const present = blockedExternalVariables.filter((name) => String(env[name] || '').trim());
  if (present.length) fail(`external/live configuration is forbidden for core tests: ${present.join(', ')}`);
};

const inspectSuite = (label, files) => {
  if (!files.length) fail(`${label} discovered zero test files`);
  let declarations = 0;
  for (const file of files) {
    const source = readFileSync(path.join(testDir, file), 'utf8');
    declarations += (source.match(/\btest\s*\(/g) || []).length;
  }
  if (declarations === 0) fail(`${label} discovered zero tests`);
  return declarations;
};

const assertCoreManifestComplete = () => {
  const discovered = readdirSync(testDir).filter((file) => file.endsWith('.test.js')).sort();
  assert.deepEqual(discovered, [...coreTests].sort(), 'backend core test manifest must include every .test.js file');
};

const runNode = (args) => {
  const result = spawnSync(process.execPath, args, {
    cwd: repoRoot,
    env: { ...process.env, NODE_ENV: 'test' },
    stdio: 'inherit'
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
};

const runSuite = (label, files) => {
  assertNoExternalTargets();
  const markers = inspectSuite(label, files);
  console.log(`[quality-gate] ${label}: ${files.length} files, ${markers} test markers; executed count follows from Node TAP`);
  runNode(['--test', ...files.map((file) => path.join('test', file))]);
};

const discoverJavaScript = (directory = repoRoot) => {
  const files = [];
  for (const entry of readdirSync(directory)) {
    if (excludedDirectories.has(entry)) continue;
    const absolute = path.join(directory, entry);
    const relative = path.relative(repoRoot, absolute);
    if (statSync(absolute).isDirectory()) files.push(...discoverJavaScript(absolute));
    else if (/\.(?:cjs|js|mjs)$/.test(entry)) files.push(relative);
  }
  return files.sort();
};

const runSyntax = () => {
  const files = discoverJavaScript();
  if (!files.length) fail('syntax discovery found zero JavaScript files');
  console.log(`[quality-gate] syntax: ${files.length} JavaScript files`);
  for (const file of files) runNode(['--check', file]);
};

const selfTest = () => {
  assert.throws(() => inspectSuite('empty-fixture', []), /zero test files/);
  assert.throws(() => assertNoExternalTargets({ DATABASE_URL: 'postgres://production.example/talkx' }), /DATABASE_URL/);
  assert.doesNotThrow(() => assertNoExternalTargets({ NODE_ENV: 'test' }));
  assert.ok(inspectSuite('core', coreTests) > 0);
  assert.ok(inspectSuite('critical', criticalTests) > 0);
  assertCoreManifestComplete();
  assert.ok(discoverJavaScript().length > 0);
  console.log('[quality-gate] self-test passed: zero-test, syntax-discovery and external-target guards fail closed');
};

const mode = process.argv[2];
if (mode === 'self-test') selfTest();
else if (mode === 'syntax') runSyntax();
else if (mode === 'core') runSuite('backend-core', coreTests);
else if (mode === 'critical') runSuite('backend-critical', criticalTests);
else fail(`unknown mode: ${mode || '<missing>'}`);
