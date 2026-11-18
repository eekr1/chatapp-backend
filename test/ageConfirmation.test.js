const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

// db.js refuses to load without a connection string; tests never query it.
process.env.DATABASE_URL ||= 'postgres://user:pass@localhost:5432/test';

const authRouter = require('../routes/auth');
const messagesTr = require('../i18n/messages.tr');
const messagesEn = require('../i18n/messages.en');

const postJson = (server, path, body, headers = {}) => new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const request = http.request({
        host: '127.0.0.1',
        port: server.address().port,
        path,
        method: 'POST',
        agent: false,
        headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(payload),
            ...headers
        }
    }, (response) => {
        let raw = '';
        response.on('data', (chunk) => { raw += chunk; });
        response.on('end', () => {
            let parsed = null;
            try { parsed = JSON.parse(raw); } catch { parsed = null; }
            resolve({ status: response.statusCode, body: parsed });
        });
    });
    request.on('error', reject);
    request.end(payload);
});

const startServer = () => new Promise((resolve) => {
    const app = express();
    app.use(express.json());
    app.use('/auth', authRouter);
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
});

test('both locales carry the 18+ confirmation message', () => {
    assert.ok(messagesTr.errors.AGE_CONFIRMATION_REQUIRED.includes('18'));
    assert.ok(messagesEn.errors.AGE_CONFIRMATION_REQUIRED.includes('18'));
});

// The age gate reads REQUIRE_AGE_CONFIRMATION per request, so tests can flip
// it between registrations; the previous value is always restored so the
// default (unset -> transition period) stays intact for the other tests.
const withAgeEnv = (value, body) => async () => {
    const previous = process.env.REQUIRE_AGE_CONFIRMATION;
    process.env.REQUIRE_AGE_CONFIRMATION = value;
    try {
        await body();
    } finally {
        if (previous === undefined) delete process.env.REQUIRE_AGE_CONFIRMATION;
        else process.env.REQUIRE_AGE_CONFIRMATION = previous;
    }
};

test('strict mode: registration is refused without an explicit 18+ confirmation', withAgeEnv('true', async () => {
    const server = await startServer();
    try {
        // Consent missing entirely: the age gate must fire before the legal
        // version validation (otherwise this request would be INVALID_INPUT).
        const missing = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: true
        });
        assert.equal(missing.status, 400);
        assert.equal(missing.body.code, 'AGE_CONFIRMATION_REQUIRED');
        assert.equal(missing.body.errorCode, 'AGE_CONFIRMATION_REQUIRED');
        assert.equal(missing.body.error, messagesEn.errors.AGE_CONFIRMATION_REQUIRED);

        const explicitFalse = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: true,
            ageConfirmed: false
        });
        assert.equal(explicitFalse.status, 400);
        assert.equal(explicitFalse.body.code, 'AGE_CONFIRMATION_REQUIRED');

        // Strict boolean: a truthy string is not consent.
        const stringTrue = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: true,
            ageConfirmed: 'true'
        });
        assert.equal(stringTrue.status, 400);
        assert.equal(stringTrue.body.code, 'AGE_CONFIRMATION_REQUIRED');

        // Turkish locale gets the Turkish copy.
        const turkish = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: true
        }, { 'x-talkx-lang': 'tr' });
        assert.equal(turkish.status, 400);
        assert.equal(turkish.body.error, messagesTr.errors.AGE_CONFIRMATION_REQUIRED);
    } finally {
        server.close();
    }
}));

test('transition mode: an omitted ageConfirmed lets legacy clients register; any explicitly sent non-true value is still rejected', withAgeEnv('false', async () => {
    const server = await startServer();
    try {
        // Field absent (legacy client): the age gate must not fire. The request
        // proceeds past it and fails on the missing legal versions instead
        // (INVALID_INPUT proves registration was not blocked by the age gate).
        const missing = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: true
        });
        assert.equal(missing.status, 400);
        assert.equal(missing.body.code, 'INVALID_INPUT');

        const explicitFalse = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: true,
            ageConfirmed: false
        });
        assert.equal(explicitFalse.status, 400);
        assert.equal(explicitFalse.body.code, 'AGE_CONFIRMATION_REQUIRED');

        // A truthy string counts as sent and is not the strict boolean.
        const stringTrue = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: true,
            ageConfirmed: 'true'
        });
        assert.equal(stringTrue.status, 400);
        assert.equal(stringTrue.body.code, 'AGE_CONFIRMATION_REQUIRED');

        // An explicit null counts as sent-but-not-confirmed.
        const explicitNull = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: true,
            ageConfirmed: null
        });
        assert.equal(explicitNull.status, 400);
        assert.equal(explicitNull.body.code, 'AGE_CONFIRMATION_REQUIRED');
    } finally {
        server.close();
    }
}));

test('consent never substitutes for the other registration guards', async () => {
    const server = await startServer();
    try {
        // Terms gate keeps its own code even when age is confirmed.
        const termsMissing = await postJson(server, '/auth/register', {
            username: 'talkxuser',
            password: 'secret123',
            terms_accepted: false,
            ageConfirmed: true
        });
        assert.equal(termsMissing.status, 400);
        assert.equal(termsMissing.body.code, 'LEGAL_ACCEPT_REQUIRED');

        // Input validation still precedes the age gate.
        const badInput = await postJson(server, '/auth/register', {
            username: 'no',
            password: 'secret123',
            terms_accepted: true
        });
        assert.equal(badInput.status, 400);
        assert.equal(badInput.body.code, 'INVALID_INPUT');
    } finally {
        server.close();
    }
});
