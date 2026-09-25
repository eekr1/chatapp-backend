const { normalizeLang } = require('./i18n');

const resolveDeliveryLocale = ({ deviceLocale = null, profileLocale = null } = {}) => {
    const normalizedDevice = normalizeLang(deviceLocale, null);
    if (normalizedDevice) {
        return { locale: normalizedDevice, source: 'device', fallbackReason: null };
    }

    const normalizedProfile = normalizeLang(profileLocale, null);
    if (normalizedProfile) {
        return { locale: normalizedProfile, source: 'profile', fallbackReason: null };
    }

    return { locale: 'en', source: 'fallback', fallbackReason: 'missing_or_unsupported' };
};

const selectLocalizedPayload = (payloadByLocale, resolution) => {
    const variants = payloadByLocale && typeof payloadByLocale === 'object' ? payloadByLocale : {};
    const requested = normalizeLang(resolution?.locale, 'en');
    const selected = variants[requested] || variants.en || null;
    if (!selected) return null;

    return {
        ...selected,
        data: {
            ...(selected.data || {}),
            renderLocale: variants[requested] ? requested : 'en',
            localeSource: resolution?.source || 'fallback',
            ...(variants[requested]
                ? {}
                : { fallbackReason: resolution?.fallbackReason || 'variant_not_available' })
        }
    };
};

module.exports = {
    resolveDeliveryLocale,
    selectLocalizedPayload
};
