'use strict';

// Anonymous room (random match) text filter.
// Masks contact details and heavy slurs before the message is relayed to the peer.
// Friend / direct messages are NOT filtered.

const MASK = '•••';

const URL_RE = /(?:https?:\/\/|www\.)[^\s]+/gi;
const SHORTLINK_RE = /\b(?:t\.me|wa\.me|discord\.gg)\/[^\s]+/gi;
const EMAIL_RE = /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com\.tr|co\.tr|com|net|org|io|me|tv|app|gg|co|tr|dev|xyz)\b(?:\/[^\s]*)?/gi;
const PHONE_RE = /(?:\+|00)?\d{2,4}[\s.-]?\d{3}[\s.-]?\d{2,4}[\s.-]?\d{0,4}/g;
const PLATFORM_RE = /\b(?:instagram|insta|snapchat|snap|telegram|tiktok|discord)\s*[:@]\s*([A-Za-z0-9._]{3,30})/gi;
const PLATFORM_SPACE_RE = /\b(?:instagram|insta|snapchat|snap|telegram|tiktok|discord)\s+([A-Za-z0-9._]*[._][A-Za-z0-9._]{2,30})/gi;
const PLATFORM_SHORT_RE = /\b(?:ig|tg)\s*[:@]\s*([A-Za-z0-9._]{3,30})/gi;

const TR_SLUR_ROOTS = ['amk', 'aq', 'orospu', 'orospucocuk', 'orospucocugu', 'sik', 'yarrak', 'pici', 'kahpe', 'surtuk', 'siktir'];
const EN_SLUR_ROOTS = ['fuck', 'fack', 'fuk', 'shit', 'bullshit', 'shithead', 'bitch', 'asshole', 'dick', 'dickhead', 'pussy', 'cunt', 'bastard', 'whore', 'faggot', 'retard', 'nigger', 'nigga', 'twat', 'slut', 'wanker', 'scumbag', 'motherfucker', 'jackass', 'dumbass', 'prick'];
const SLUR_ROOTS = [...TR_SLUR_ROOTS, ...EN_SLUR_ROOTS];
const SLUR_SUFFIXES = ['s', 'es', 'ed', 'er', 'ers', 'a', 'e', 'i', 'im', 'in', 'you', 'dan', 'den', 'ten', 'ler', 'lar', 'lara', 'lere', 'le', 'la', 'ci', 'ya', 'ye', 'iz', 'mis', 'din', 'dun', 'sun', 'sac', 'ik', 'ing', 'head', 'ies'];
const TR_MAP = { 'ı': 'i', 'ş': 's', 'ğ': 'g', 'ü': 'u', 'ö': 'o', 'ç': 'c' };
const LEET_MAP = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };

const normalizeWord = (word) => {
    let out = String(word || '').toLowerCase();
    out = out.replace(/i̇/g, 'i'); // dotted capital I (İ) lowercases to i + combining dot
    out = out.replace(/[ışğüöç]/g, (ch) => TR_MAP[ch] || ch);
    out = out.replace(/[013457@$]/g, (ch) => LEET_MAP[ch] || ch);
    out = out.replace(/[^a-z]/g, '');
    return out;
};

// Root form of a word: drops an -e/-a style plural/suffix ending so that
// "fucking" -> "fucking" -> "fuck" style forms still match a known root.
const stripEnding = (word) => {
    if (word.length > 4 && word.endsWith('ing')) return word.slice(0, -3);
    return word;
};

const collapseRepeats = (word) => word.replace(/(.)\1+/g, '$1');

const matchSlurRoot = (normalized, collapsed) => {
    for (const root of SLUR_ROOTS) {
        if (collapsed === root || normalized === root) return root;
        const stem = stripEnding(collapsed);
        if (stem === root) return root;
        if (normalized.length > root.length
            && normalized.startsWith(root)
            && SLUR_SUFFIXES.includes(normalized.slice(root.length))) return root;
    }
    return null;
};

const maskSlurs = (text) => {
    let masked = false;
    const result = String(text).replace(/[\p{L}\p{N}@$._-]+/gu, (token) => {
        const normalized = normalizeWord(token);
        if (!normalized) return token;
        const root = matchSlurRoot(normalized, collapseRepeats(normalized));
        if (!root) return token;
        masked = true;
        return `${token[0]}${MASK}`;
    });
    return { text: result, masked };
};

const maskContactDetails = (text) => {
    const reasons = [];
    let out = String(text);

    out = out.replace(SHORTLINK_RE, () => { reasons.push('url'); return MASK; });
    out = out.replace(URL_RE, () => { reasons.push('url'); return MASK; });
    out = out.replace(EMAIL_RE, () => { reasons.push('email'); return MASK; });
    out = out.replace(PLATFORM_RE, (match, username) => {
        reasons.push('platform');
        const prefix = match.slice(0, match.lastIndexOf(username)).replace(/\s+$/, '');
        return `${prefix} ${MASK}`;
    });
    out = out.replace(PLATFORM_SPACE_RE, (match, username) => {
        reasons.push('platform');
        const prefix = match.slice(0, match.lastIndexOf(username)).replace(/\s+$/, '');
        return `${prefix} ${MASK}`;
    });
    out = out.replace(PLATFORM_SHORT_RE, (match, username) => {
        reasons.push('platform');
        const prefix = match.slice(0, match.lastIndexOf(username)).replace(/\s+$/, '');
        return `${prefix} ${MASK}`;
    });
    out = out.replace(DOMAIN_RE, () => { reasons.push('url'); return MASK; });
    out = out.replace(PHONE_RE, (match) => {
        const digits = (match.match(/\d/g) || []).length;
        if (digits < 10 || digits > 15) return match;
        reasons.push('phone');
        return MASK;
    });

    return { text: out, reasons };
};

const isEnabled = (env = process.env) => String(env?.TEXT_FILTER_ENABLED ?? 'true').trim().toLowerCase() !== 'false';

const filterAnonMessage = (text) => {
    const source = typeof text === 'string' ? text : '';
    if (!source) return { text: source, masked: false, reasons: [] };

    const contact = maskContactDetails(source);
    const slur = maskSlurs(contact.text);
    const reasons = [...contact.reasons];
    if (slur.masked) reasons.push('slur');

    return {
        text: slur.text,
        masked: reasons.length > 0,
        reasons: [...new Set(reasons)]
    };
};

module.exports = { filterAnonMessage, isEnabled };
