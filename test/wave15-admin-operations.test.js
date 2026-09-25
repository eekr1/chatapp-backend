const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
    buildSupportFingerprint,
    isSafeSupportMediaType,
    locationState,
    maskEmail,
    maskIdentifier,
    maskIp,
    validateWorkflowTransition
} = require('../utils/adminOperationsContract');
const { ADMIN_CAPABILITIES, capabilityFor } = require('../utils/adminSecurity');

test('sensitive admin values are masked without returning the original value', () => {
    assert.equal(maskIp('192.0.2.44'), '192.0.*.*');
    assert.equal(maskIdentifier('device-secret-123456'), 'devi…3456');
    assert.equal(maskEmail('person@example.com'), 'p***n@example.com');
    assert.doesNotMatch(maskIp('192.0.2.44'), /2\.44/);
});

test('geo states distinguish resolved, stale, unresolved and unavailable', () => {
    const now = Date.parse('2026-09-25T12:00:00.000Z');
    assert.equal(locationState({ source: 'ipapi.co', resolvedAt: '2026-09-25T11:00:00.000Z', country: 'TR' }, { now }), 'resolved');
    assert.equal(locationState({ source: 'ipapi.co', resolvedAt: '2026-01-01T00:00:00.000Z', country: 'TR' }, { now }), 'stale');
    assert.equal(locationState({ source: 'unresolved' }, { now }), 'unresolved');
    assert.equal(locationState({}, { now }), 'not_available');
});

test('support fingerprint is deterministic and workflow transitions are explicit', () => {
    const input = { subject: ' Connection ', lastErrorCode: ' TIMEOUT ', platform: 'Android', appVersion: '1.2.3' };
    assert.equal(buildSupportFingerprint(input), buildSupportFingerprint({ ...input, subject: 'connection' }));
    assert.equal(buildSupportFingerprint({}), null);
    assert.deepEqual(validateWorkflowTransition({ current: 'new', next: 'investigating' }), {
        ok: true, noOp: false, from: 'new', to: 'investigating'
    });
    assert.equal(validateWorkflowTransition({ current: 'resolved', next: 'new' }).ok, false);
});

test('support media allowlist rejects scriptable and generic payloads', () => {
    assert.equal(isSafeSupportMediaType('image/jpeg'), true);
    assert.equal(isSafeSupportMediaType('video/mp4'), true);
    assert.equal(isSafeSupportMediaType('image/svg+xml'), false);
    assert.equal(isSafeSupportMediaType('text/html'), false);
});

test('Wave 15 migration is additive and contains lifecycle history and guards', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'db.js'), 'utf8');
    const start = source.indexOf("version: '008'");
    const migration = source.slice(start);
    assert.ok(start >= 0);
    assert.match(migration, /wave15_admin_operations/);
    assert.match(migration, /workflow_status/);
    assert.match(migration, /workflow_revision/);
    assert.match(migration, /support_report_history/);
    assert.match(migration, /legal_hold/);
});

test('profile and report routes remove default sensitive data and disable hard delete', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'admin.js'), 'utf8');
    const profileStart = source.indexOf("} else if (type === 'profiles')");
    const reportStart = source.indexOf("} else if (type === 'app_reports')", profileStart);
    const profileRoute = source.slice(profileStart, reportStart);
    const reportEnd = source.indexOf("router.get('/profile-details", reportStart);
    const reportRoute = source.slice(reportStart, reportEnd);
    assert.match(profileRoute, /registration_ip: _sensitiveRegistrationIp/);
    assert.match(profileRoute, /location_label: _possiblyIpBearingLocationLabel/);
    assert.match(profileRoute, /location_state/);
    assert.doesNotMatch(reportRoute.match(/SELECT[\s\S]*?FROM support_reports/)?.[0] || '', /contact_email|description/);
    assert.match(source, /SUPPORT_REPORT_HARD_DELETE_DISABLED/);
    assert.match(source, /router\.patch\('\/support-report\/:id\/workflow'/);
    assert.match(source, /X-Content-Type-Options/);
    assert.match(source, /Cache-Control', 'private, no-store'/);
});

test('profile detail relations use relation dates and independent section UI', () => {
    const api = fs.readFileSync(path.join(__dirname, '..', 'admin.js'), 'utf8');
    const ui = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');
    assert.match(api, /f\.created_at AS relationship_created_at/);
    assert.match(api, /blockedByUser: outgoing\.rows, blockingUser: incoming\.rows/);
    assert.match(ui, /Promise\.allSettled/);
    assert.match(ui, /Sona erme \/ son kullanma tarihi/);
    assert.match(ui, /Session aktivitesi authoritative revocation\/last-use verisi olmadigi icin bilinmiyor/);
    assert.doesNotMatch(ui, /registration_ip/);
    assert.match(ui, /id="bulk-toolbar" style="display:\$\{bulkSelectedUserIds\.size\?'flex':'none'\}"/);
});

test('support workflow mutations are moderation actions, not sensitive reads', () => {
    assert.equal(capabilityFor('GET', '/support-report/id'), ADMIN_CAPABILITIES.SENSITIVE_READ);
    assert.equal(capabilityFor('PATCH', '/support-report/id/workflow'), ADMIN_CAPABILITIES.ACTION);
    assert.equal(capabilityFor('DELETE', '/support-report/id'), ADMIN_CAPABILITIES.ACTION);
});
