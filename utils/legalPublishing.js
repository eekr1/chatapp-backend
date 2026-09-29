const crypto = require('crypto');
const { normalizeLegalContent, validateLegalContentPayload } = require('./legalContent');

const LEGAL_DOCUMENT_KEYS = Object.freeze(['privacy', 'terms', 'childSafety', 'footer']);
const LEGAL_CHANGE_CLASSES = Object.freeze(['typo_format', 'clarification', 'material']);
const LEGAL_PLACEHOLDER_PATTERNS = Object.freeze([
    /panelden\s+guncellenebilir/i,
    /can\s+be\s+updated\s+from\s+the\s+admin\s+panel/i,
    /placeholder/i,
    /lorem ipsum/i
]);

const clone = (value) => JSON.parse(JSON.stringify(value));

const assertDocumentKey = (value) => {
    const key = String(value || '').trim();
    if (!LEGAL_DOCUMENT_KEYS.includes(key)) throw new Error('Gecersiz yasal belge anahtari.');
    return key;
};

const extractLegalSection = (content, documentKey) => {
    const key = assertDocumentKey(documentKey);
    const normalized = normalizeLegalContent(content);
    if (key === 'footer') return { footer: clone(normalized.footer) };
    return {
        version: key === 'privacy' || key === 'terms' ? normalized.versions[key] : null,
        document: clone(normalized.documents[key])
    };
};

const applyLegalSection = (content, documentKey, section) => {
    const key = assertDocumentKey(documentKey);
    const next = clone(normalizeLegalContent(content));
    if (key === 'footer') {
        next.footer = clone(section?.footer || {});
    } else {
        next.documents[key] = clone(section?.document || {});
        if (key === 'privacy' || key === 'terms') next.versions[key] = String(section?.version || '').trim();
    }
    const validation = validateLegalContentPayload(next);
    if (!validation.ok) throw new Error(validation.error);
    return validation.value;
};

const stableSort = (value) => {
    if (Array.isArray(value)) return value.map(stableSort);
    if (!value || typeof value !== 'object') return value;
    return Object.keys(value).sort().reduce((result, key) => {
        result[key] = stableSort(value[key]);
        return result;
    }, {});
};

const hashLegalContent = (content) => crypto
    .createHash('sha256')
    .update(JSON.stringify(stableSort(normalizeLegalContent(content))))
    .digest('hex');

const containsLegalPlaceholder = (section) => {
    const values = Object.values(flattenStrings(section));
    return values.some((value) => LEGAL_PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(String(value ?? ''))));
};

const flattenStrings = (value, prefix = '', output = {}) => {
    if (typeof value === 'string' || value === null || typeof value === 'number' || typeof value === 'boolean') {
        output[prefix] = value;
        return output;
    }
    if (!value || typeof value !== 'object') return output;
    for (const [key, child] of Object.entries(value)) {
        flattenStrings(child, prefix ? `${prefix}.${key}` : key, output);
    }
    return output;
};

const buildLegalDiff = (liveContent, draftContent, documentKey) => {
    const live = flattenStrings(extractLegalSection(liveContent, documentKey));
    const draft = flattenStrings(extractLegalSection(draftContent, documentKey));
    const fields = [...new Set([...Object.keys(live), ...Object.keys(draft)])]
        .filter((field) => live[field] !== draft[field])
        .map((field) => ({
            field,
            before: live[field] ?? null,
            after: draft[field] ?? null,
            characterDelta: String(draft[field] ?? '').length - String(live[field] ?? '').length
        }));
    return {
        changed: fields.length > 0,
        changedFieldCount: fields.length,
        fields
    };
};

const evaluateLegalPublication = ({ liveContent, draftSection, documentKey, changeClass }) => {
    const key = assertDocumentKey(documentKey);
    const normalizedClass = String(changeClass || '').trim();
    if (!LEGAL_CHANGE_CLASSES.includes(normalizedClass)) throw new Error('Gecersiz degisiklik sinifi.');
    if (containsLegalPlaceholder(draftSection)) throw new Error('Taslak gecici veya placeholder icerik barindiriyor.');
    const nextContent = applyLegalSection(liveContent, key, draftSection);
    const diff = buildLegalDiff(liveContent, nextContent, key);
    if (!diff.changed) throw new Error('Taslak ile canli icerik arasinda degisiklik yok.');
    const versionBefore = key === 'privacy' || key === 'terms' ? normalizeLegalContent(liveContent).versions[key] : null;
    const versionAfter = key === 'privacy' || key === 'terms' ? nextContent.versions[key] : null;
    const versionChanged = versionBefore !== versionAfter;
    if ((key === 'privacy' || key === 'terms') && normalizedClass === 'material' && !versionChanged) {
        throw new Error('Maddi degisiklikte belge surumu artirilmalidir.');
    }
    return {
        nextContent,
        diff,
        versionBefore,
        versionAfter,
        versionChanged,
        requiresReaccept: (key === 'privacy' || key === 'terms') && versionChanged
    };
};

module.exports = {
    LEGAL_DOCUMENT_KEYS,
    LEGAL_CHANGE_CLASSES,
    assertDocumentKey,
    extractLegalSection,
    applyLegalSection,
    hashLegalContent,
    containsLegalPlaceholder,
    buildLegalDiff,
    evaluateLegalPublication
};
