const { clampInteger } = require('./runtimeConfig');

const resolvePerformancePolicy = (env = process.env) => ({
    minimumPercentileSamples: clampInteger(env.PERF_MIN_PERCENTILE_SAMPLES, 20, 3, 10000),
    p95WarningMs: clampInteger(env.PERF_P95_WARNING_MS, 800, 50, 60000),
    p95CriticalMs: clampInteger(env.PERF_P95_CRITICAL_MS, 1500, 100, 120000),
    errorWarningRate: clampInteger(env.PERF_ERROR_WARNING_PERCENT, 2, 1, 50),
    errorCriticalRate: clampInteger(env.PERF_ERROR_CRITICAL_PERCENT, 5, 1, 100),
    staleAfterMinutes: clampInteger(env.PERF_STALE_AFTER_MINUTES, 15, 2, 1440)
});

const finiteOrNull = (value) => {
    if (value === null || value === undefined || value === '') return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
};

const routeKey = (row = {}) => `${String(row.method || 'GET').toUpperCase()} ${String(row.route || '-')}`;

const buildRouteImpact = (slowRows = [], errorRows = []) => {
    const routes = new Map();
    for (const row of [...errorRows, ...slowRows]) {
        const key = routeKey(row);
        routes.set(key, { ...(routes.get(key) || {}), ...row, key });
    }
    return [...routes.values()].map((row) => {
        const requests = finiteOrNull(row.req_count) ?? finiteOrNull(row.sample_count) ?? 0;
        const errors = finiteOrNull(row.error_count) || 0;
        const latency = finiteOrNull(row.p95_ms) ?? finiteOrNull(row.avg_ms) ?? 0;
        return { ...row, impact_score: Math.round((errors * 1000000) + (requests * latency)) };
    }).sort((a, b) => b.impact_score - a.impact_score || a.key.localeCompare(b.key));
};

const buildPerformanceOverview = ({
    hours,
    totals,
    previousTotals,
    percentiles,
    topSlowRoutes = [],
    topErrorRoutes = [],
    partial = false,
    now = new Date(),
    policy = resolvePerformancePolicy()
}) => {
    const totalRequests = finiteOrNull(totals?.total_requests) || 0;
    const errorRequests = finiteOrNull(totals?.error_requests) || 0;
    const sampledRequests = finiteOrNull(percentiles?.sample_count) || 0;
    const hasTraffic = totalRequests > 0;
    const sufficientSamples = sampledRequests >= policy.minimumPercentileSamples;
    const p50 = sufficientSamples ? finiteOrNull(percentiles?.p50_ms) : null;
    const p95 = sufficientSamples ? finiteOrNull(percentiles?.p95_ms) : null;
    const p99 = sufficientSamples ? finiteOrNull(percentiles?.p99_ms) : null;
    const errorRate = hasTraffic ? Math.round((errorRequests * 10000) / totalRequests) / 100 : null;
    const lastUpdatedAt = totals?.last_bucket_at ? new Date(totals.last_bucket_at) : null;
    const stale = Boolean(lastUpdatedAt && Number.isFinite(lastUpdatedAt.getTime())
        && now.getTime() - lastUpdatedAt.getTime() > policy.staleAfterMinutes * 60000);
    const dataState = partial ? 'partial' : (!hasTraffic ? 'no_data' : (stale ? 'stale' : 'fresh'));
    const confidence = !hasTraffic ? 'none' : (sufficientSamples ? 'sufficient' : 'low');
    let evaluation = 'healthy';
    if (!hasTraffic) evaluation = 'no_data';
    else if (!sufficientSamples) evaluation = 'low_confidence';
    else if (p95 >= policy.p95CriticalMs || errorRate >= policy.errorCriticalRate) evaluation = 'critical';
    else if (p95 >= policy.p95WarningMs || errorRate >= policy.errorWarningRate) evaluation = 'warning';

    const previousRequests = finiteOrNull(previousTotals?.total_requests) || 0;
    const previousErrors = finiteOrNull(previousTotals?.error_requests) || 0;

    return {
        hours,
        window: { hours, previousHours: hours },
        data_state: dataState,
        confidence,
        evaluation,
        last_updated_at: lastUpdatedAt?.toISOString() || null,
        thresholds: {
            minimum_percentile_samples: policy.minimumPercentileSamples,
            p95_warning_ms: policy.p95WarningMs,
            p95_critical_ms: policy.p95CriticalMs,
            error_warning_rate: policy.errorWarningRate,
            error_critical_rate: policy.errorCriticalRate
        },
        total_requests: totalRequests,
        error_requests: errorRequests,
        error_rate: errorRate,
        slow_requests: finiteOrNull(totals?.slow_requests) || 0,
        avg_ms: hasTraffic ? Math.round(((finiteOrNull(totals?.total_duration_ms) || 0) / totalRequests) * 10) / 10 : null,
        sample_count: sampledRequests,
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
        previous_period: {
            total_requests: previousRequests,
            error_requests: previousErrors,
            error_rate: previousRequests > 0 ? Math.round((previousErrors * 10000) / previousRequests) / 100 : null
        },
        top_slow_routes: topSlowRoutes,
        top_error_routes: topErrorRoutes,
        route_impact: buildRouteImpact(topSlowRoutes, topErrorRoutes),
        metric_scope: 'backend_api',
        platform: 'unknown',
        release: 'unknown'
    };
};

module.exports = {
    finiteOrNull,
    resolvePerformancePolicy,
    buildRouteImpact,
    buildPerformanceOverview
};
