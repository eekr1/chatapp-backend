import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const testDir = path.join(repoRoot, 'test');
const coreTests = [
  'mobile-redesign.test.js',
  'admin-legal-publishing.test.js',
  'admin-notification-contract.test.js',
  'match-country-auto.test.js',
  'matchQuota.test.js',
  'adRewardsSsv.test.js',
  'ageConfirmation.test.js',
  'textFilter.test.js',
  'nightly-backup.test.js',
  'poller-private-repo-auth.test.js',
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
  'wave15-admin-operations.test.js',
  'poller-migration.test.js'
];
const criticalTests = [
  'mobile-redesign.test.js',
  'admin-legal-publishing.test.js',
  'admin-notification-contract.test.js',
  'match-country-auto.test.js',
  'nightly-backup.test.js',
  'poller-private-repo-auth.test.js',
  'wave02-platform.test.js',
  'wave05-recovery-presence.test.js',
  'wave07-search-lifecycle.test.js',
  'wave08-match-scope.test.js',
  'wave09-pending-match.test.js',
  'wave10-direct-message.test.js',
  'wave12-legal-account.test.js'
];
// Test files declared in a manifest but authored in a parallel lane, so they are not in the
// tree yet. They are skipped instead of crashing the gate, and they run as ordinary suite
// members as soon as the file lands. Any other missing manifest file fails the gate closed.
const pendingTests = ['textFilter.test.js'];
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

const testFilePath = (file) => path.join(testDir, file);

// Split a manifest into the files that exist in the tree and the ones that are still pending.
const resolveSuite = (files) => {
  const present = [];
  const pending = [];
  for (const file of files) {
    if (existsSync(testFilePath(file))) present.push(file);
    else pending.push(file);
  }
  return { present, pending };
};

const assertDeclaredFilesResolvable = (label, files) => {
  const { present, pending } = resolveSuite(files);
  const unexpected = pending.filter((file) => !pendingTests.includes(file));
  if (unexpected.length) fail(`${label} manifest declares missing test files: ${unexpected.join(', ')}`);
  return { present, pending };
};

const inspectSuite = (label, files) => {
  const { present } = resolveSuite(files);
  if (!present.length) fail(`${label} discovered zero test files`);
  let declarations = 0;
  for (const file of present) {
    const source = readFileSync(testFilePath(file), 'utf8');
    declarations += (source.match(/\btest\s*\(/g) || []).length;
  }
  if (declarations === 0) fail(`${label} discovered zero tests`);
  return declarations;
};

const assertCoreManifestComplete = () => {
  const discovered = readdirSync(testDir).filter((file) => file.endsWith('.test.js')).sort();
  const declared = [...coreTests].sort();
  const missing = discovered.filter((file) => !declared.includes(file));
  if (missing.length) fail(`backend core test manifest must include every .test.js file: ${missing.join(', ')}`);
  const { present, pending } = resolveSuite(coreTests);
  const unapproved = pending.filter((file) => !pendingTests.includes(file));
  if (unapproved.length) fail(`backend core test manifest lists missing test files: ${unapproved.join(', ')}`);
  const extra = present.filter((file) => !discovered.includes(file));
  if (extra.length) fail(`backend core test manifest lists files that do not exist: ${extra.join(', ')}`);
  return pending;
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
  const { present, pending } = assertDeclaredFilesResolvable(label, files);
  const markers = inspectSuite(label, files);
  const skipped = pending.length ? `, ${pending.length} pending (${pending.join(', ')})` : '';
  console.log(`[quality-gate] ${label}: ${present.length} files${skipped}, ${markers} test markers; executed count follows from Node TAP`);
  runNode(['--test', ...present.map((file) => path.join('test', file))]);
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
  // A missing manifest file fails closed unless it is an approved pending entry.
  assert.throws(() => assertDeclaredFilesResolvable('fixture', ['not-a-real-suite.test.js']), /missing test files/);
  assert.doesNotThrow(() => assertDeclaredFilesResolvable('fixture', pendingTests));
  assert.ok(discoverJavaScript().length > 0);
  console.log('[quality-gate] self-test passed: zero-test, syntax-discovery and external-target guards fail closed');
};

const mode = process.argv[2];
if (mode === 'self-test') selfTest();
else if (mode === 'syntax') runSyntax();
else if (mode === 'core') runSuite('backend-core', coreTests);
else if (mode === 'critical') runSuite('backend-critical', criticalTests);
else fail(`unknown mode: ${mode || '<missing>'}`);
