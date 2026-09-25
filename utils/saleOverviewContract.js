const METRIC_STATES = Object.freeze({
    VALUE: 'value',
    NO_DATA: 'no_data',
    UNAVAILABLE: 'unavailable'
});

const normalizeCount = (value) => {
    const count = Number(value);
    if (!Number.isFinite(count) || count < 0) return null;
    return Math.floor(count);
};

const metricBase = ({ key, label, unit, source, window, note = null }) => ({
    key,
    label,
    unit,
    source,
    window,
    note
});

const countMetric = (definition, value) => {
    const count = normalizeCount(value);
    if (count === null) return unavailableMetric(definition);
    return {
        ...metricBase(definition),
        state: METRIC_STATES.VALUE,
        value: count
    };
};

const noDataMetric = (definition, note) => ({
    ...metricBase({ ...definition, note: note || definition.note || null }),
    state: METRIC_STATES.NO_DATA,
    value: null
});

const unavailableMetric = (definition, note) => ({
    ...metricBase({ ...definition, note: note || definition.note || null }),
    state: METRIC_STATES.UNAVAILABLE,
    value: null
});

const identifiedOutcomeMetric = (definition, { identifiedCount, rawEventCount }) => {
    const identified = normalizeCount(identifiedCount);
    const raw = normalizeCount(rawEventCount);
    if (identified === null || raw === null) return unavailableMetric(definition);
    if (raw > 0 && identified === 0) {
        return noDataMetric(definition, 'Pencerede yalnız canonical kimliği olmayan eski kayıtlar var.');
    }
    return countMetric(definition, identified);
};

const buildSaleOverview = ({ generatedAt = new Date(), metrics = [] } = {}) => {
    const metricMap = Object.fromEntries(metrics.map((metric) => [metric.key, metric]));
    const states = metrics.map((metric) => metric.state);
    const availableCount = states.filter((state) => state === METRIC_STATES.VALUE).length;
    const status = availableCount === states.length
        ? 'complete'
        : (availableCount === 0 ? 'unavailable' : 'partial');
    return {
        contractVersion: 'sale-overview-v1',
        generatedAt: new Date(generatedAt).toISOString(),
        status,
        metrics: metricMap
    };
};

module.exports = {
    METRIC_STATES,
    buildSaleOverview,
    countMetric,
    identifiedOutcomeMetric,
    noDataMetric,
    unavailableMetric
};
