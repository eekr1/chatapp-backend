const path = require('path');
const { normalizeCountryCode } = require('./countryPolicy');
const { normalizeIp } = require('./clientIp');

process.env.ILA_FIELDS = 'country';
process.env.ILA_IP_LOCATION_DB = 'user';
process.env.ILA_DATA_DIR = path.join(__dirname, '..', 'data', 'ip-country');
process.env.ILA_AUTO_UPDATE = 'false';
process.env.ILA_SILENT = 'true';

// The database is committed with the backend, so requiring this module never downloads data.
const { lookup } = require('ip-location-api');
const SOURCE = 'local:user-country';

const isNonPublicIp = (ip) => {
    if (!ip || ip === '::1') return true;
    if (/^10\./.test(ip) || /^127\./.test(ip) || /^169\.254\./.test(ip) || /^192\.168\./.test(ip)) return true;
    const private172 = /^172\.(\d+)\./.exec(ip);
    if (private172 && Number(private172[1]) >= 16 && Number(private172[1]) <= 31) return true;
    const lower = ip.toLowerCase();
    return lower.startsWith('fc') || lower.startsWith('fd') || /^fe[89ab]/.test(lower);
};

const resolveLocalCountry = (ipValue) => {
    const ip = normalizeIp(ipValue);
    if (!ip || isNonPublicIp(ip)) return { ok: false, countryCode: null, source: ip ? 'private' : 'none' };
    try {
        const countryCode = normalizeCountryCode(lookup(ip)?.country);
        return countryCode
            ? { ok: true, countryCode, source: SOURCE }
            : { ok: false, countryCode: null, source: 'unresolved' };
    } catch {
        return { ok: false, countryCode: null, source: 'unresolved' };
    }
};

module.exports = { SOURCE, isNonPublicIp, resolveLocalCountry };
