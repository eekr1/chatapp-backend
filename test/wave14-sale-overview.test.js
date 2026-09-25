const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
    METRIC_STATES,
    buildSaleOverview,
    countMetric,
    identifiedOutcomeMetric,
    unavailableMetric
} = require('../utils/saleOverviewContract');

const definition = (key) => ({
    key,
    label: key,
    unit: 'count',
    source: 'fixture',
    window: { kind: 'rolling', hours: 24, label: 'Son 24 saat' }
});

test('real zero remains a value with explicit source and time window', () => {
    const metric = countMetric(definition('searches24h'), 0);
    assert.equal(metric.state, METRIC_STATES.VALUE);
    assert.equal(metric.value, 0);
    assert.equal(metric.source, 'fixture');
    assert.equal(metric.window.hours, 24);
});

test('legacy events without canonical identity are no-data rather than a fake zero', () => {
    const metric = identifiedOutcomeMetric(definition('matches24h'), {
        identifiedCount: 0,
        rawEventCount: 2
    });
    assert.equal(metric.state, METRIC_STATES.NO_DATA);
    assert.equal(metric.value, null);
    assert.match(metric.note, /canonical kimliği olmayan/);
});

test('provider failure is unavailable and makes the overview partial', () => {
    const overview = buildSaleOverview({
        generatedAt: '2026-09-25T12:00:00.000Z',
        metrics: [
            countMetric(definition('users'), 7),
            unavailableMetric(definition('online'))
        ]
    });
    assert.equal(overview.status, 'partial');
    assert.equal(overview.metrics.users.value, 7);
    assert.equal(overview.metrics.online.state, METRIC_STATES.UNAVAILABLE);
    assert.equal(overview.generatedAt, '2026-09-25T12:00:00.000Z');
});

test('sale overview route counts canonical search and match identities and keeps providers independent', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'admin.js'), 'utf8');
    const routeStart = source.indexOf("router.get('/sale-overview'");
    const routeEnd = source.indexOf("router.get('/online-users'", routeStart);
    const route = source.slice(routeStart, routeEnd);
    assert.ok(routeStart >= 0 && routeEnd > routeStart);
    assert.match(route, /COUNT\(DISTINCT NULLIF\(metadata->>'search_id', ''\)\)/);
    assert.match(route, /COUNT\(DISTINCT match_id\)/);
    assert.match(route, /Promise\.allSettled/);
    assert.doesNotMatch(route, /res\.status\(500\)\.json\(\{ error: e\.message \}\)/);
});

test('dashboard consumes the minimal overview without default raw event or hourly tables', () => {
    const source = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');
    const dashboardStart = source.indexOf('async function loadDashboardTab()');
    const dashboardEnd = source.indexOf('async function loadContent()', dashboardStart);
    const dashboard = source.slice(dashboardStart, dashboardEnd);
    assert.match(dashboard, /fetchSaleOverview\(\)/);
    assert.match(dashboard, /searches24h/);
    assert.match(dashboard, /matches24h/);
    assert.doesNotMatch(dashboard, /analytics\/timeseries|analytics\/recent|table-scroll/);
    assert.match(source, /metric\?\.state==='value'/);
    assert.match(source, /metric\?\.state==='no_data'/);
    assert.match(source, /push_delivery_logs \| Son 60 dakika/);
    assert.match(source, /http_request_metrics_minute \| Son 60 dakika/);
});
