const POLICY_VERSION = 'match-country-v1';
const ISO_ALPHA2 = new Set((
    'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ ' +
    'CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR ' +
    'GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM ' +
    'JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP ' +
    'MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY ' +
    'QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO ' +
    'TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'
).split(/\s+/));

const STRICT_ALIASES = new Map([
    ['TR', 'TR'], ['TURKEY', 'TR'], ['TURKIYE', 'TR'],
    ['DE', 'DE'], ['GERMANY', 'DE'], ['ALMANYA', 'DE'],
    ['GB', 'GB'], ['UNITED KINGDOM', 'GB'], ['UK', 'GB'],
    ['US', 'US'], ['UNITED STATES', 'US'], ['USA', 'US'],
    ['FR', 'FR'], ['FRANCE', 'FR'], ['FRANSA', 'FR'],
    ['BR', 'BR'], ['BRAZIL', 'BR'], ['BREZILYA', 'BR']
]);
const INELIGIBLE_SOURCES = new Set(['unresolved', 'none', 'local', 'private', 'unknown']);

const normalizeCandidate = (value) => String(value || '')
    .trim()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/ı/g, 'i')
    .replace(/\s+/g, ' ')
    .toUpperCase();
const normalizeCountryCode = (value) => {
    const normalized = normalizeCandidate(value);
    const code = STRICT_ALIASES.get(normalized) || (ISO_ALPHA2.has(normalized) ? normalized : null);
    return code && ISO_ALPHA2.has(code) ? code : null;
};
const evaluateCountryCandidate = ({ country, source, observedAt, now = new Date(), maxAgeMs = 30 * 24 * 60 * 60 * 1000 }) => {
    const normalizedSource = String(source || '').trim().toLowerCase();
    const code = normalizeCountryCode(country);
    if (!code || INELIGIBLE_SOURCES.has(normalizedSource)) {
        return { countryCode: null, status: 'unavailable', confidence: 'unknown', policyVersion: POLICY_VERSION };
    }
    const observed = observedAt ? new Date(observedAt) : null;
    if (!observed || Number.isNaN(observed.getTime()) || now.getTime() - observed.getTime() > maxAgeMs) {
        return { countryCode: code, status: 'stale', confidence: 'inferred', policyVersion: POLICY_VERSION };
    }
    return { countryCode: code, status: 'eligible', confidence: 'policy_verified', policyVersion: POLICY_VERSION };
};
const displayCountry = (code, locale = 'en') => {
    if (!ISO_ALPHA2.has(String(code || '').toUpperCase())) return null;
    try { return new Intl.DisplayNames([locale === 'tr' ? 'tr' : 'en'], { type: 'region' }).of(code); }
    catch { return code; }
};

module.exports = { POLICY_VERSION, ISO_ALPHA2, normalizeCountryCode, evaluateCountryCandidate, displayCountry };
