const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { buildAuthHeaders, buildGitAuthEnv, readTokenFile } = require('../ops/windows/poller.cjs');

const base = { 'User-Agent': 'TalkX-PC-Deploy', Accept: 'application/vnd.github+json' };

test('poller API headers stay anonymous without a token', () => {
    for (const token of [null, '', '   ']) {
        const headers = buildAuthHeaders(base, token);
        assert.deepEqual(headers, base);
        assert.equal('Authorization' in headers, false);
    }
});

test('poller API headers gain a Bearer token without mutating the base object', () => {
    const headers = buildAuthHeaders(base, 'github_fine_grained_token');
    assert.equal(headers.Authorization, 'Bearer github_fine_grained_token');
    assert.equal(headers['User-Agent'], 'TalkX-PC-Deploy');
    assert.deepEqual(base, { 'User-Agent': 'TalkX-PC-Deploy', Accept: 'application/vnd.github+json' });
});

test('git auth env is empty without a token', () => {
    for (const token of [null, '', '   ']) assert.deepEqual(buildGitAuthEnv(token), {});
});

test('git clone auth travels only via GIT_CONFIG_* env, never raw in a value', () => {
    const env = buildGitAuthEnv('tok123');
    assert.equal(env.GIT_CONFIG_COUNT, '1');
    assert.equal(env.GIT_CONFIG_KEY_0, 'http.extraHeader');
    const expected = 'Authorization: Basic ' + Buffer.from('x-access-token:tok123', 'utf8').toString('base64');
    assert.equal(env.GIT_CONFIG_VALUE_0, expected);
    assert.equal(env.GIT_CONFIG_VALUE_0.includes('tok123'), false);
});

test('readTokenFile trims the file content and tolerates missing or empty files', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'talkx-token-'));
    try {
        const file = path.join(dir, 'github-readonly.token');
        fs.writeFileSync(file, '  secret-token-value\r\n');
        assert.equal(readTokenFile(file), 'secret-token-value');
        fs.writeFileSync(file, '\n');
        assert.equal(readTokenFile(file), null);
        assert.equal(readTokenFile(path.join(dir, 'missing.token')), null);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});