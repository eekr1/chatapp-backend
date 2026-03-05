const LEGAL_SETTINGS_KEY = 'legal_content_v1';

const DEFAULT_LEGAL_CONTENT = Object.freeze({
    footer: Object.freeze({
        urls: Object.freeze({
            privacy: '/privacy-policy',
            terms: '/terms-of-use'
        }),
        tr: Object.freeze({
            tagline: 'Kimligini gizle, ozgurce konus.',
            privacyLabel: 'Gizlilik Politikasi',
            termsLabel: 'Kullanim Sartlari'
        }),
        en: Object.freeze({
            tagline: 'Hide your identity, speak freely.',
            privacyLabel: 'Privacy Policy',
            termsLabel: 'Terms of Use'
        })
    }),
    versions: Object.freeze({
        terms: 'v1',
        privacy: 'v1'
    }),
    documents: Object.freeze({
        privacy: Object.freeze({
            tr: Object.freeze({
                title: 'Gizlilik Politikasi',
                content: 'Bu metin admin panelinden guncellenebilir.\n\nKisisel verilerinizi yalnizca hizmetin sunulmasi, guvenlik ve yasal yukumlulukler kapsaminda isleriz.'
            }),
            en: Object.freeze({
                title: 'Privacy Policy',
                content: 'This text can be updated from the admin panel.\n\nWe process your personal data only for service delivery, security, and legal compliance.'
            })
        }),
        terms: Object.freeze({
            tr: Object.freeze({
                title: 'Kullanim Sartlari',
                content: 'Bu metin admin panelinden guncellenebilir.\n\nUygulamayi kullanarak topluluk kurallarina ve gecerli mevzuata uygun davranmayi kabul edersiniz.'
            }),
            en: Object.freeze({
                title: 'Terms of Use',
                content: 'This text can be updated from the admin panel.\n\nBy using the app, you agree to follow community rules and applicable laws.'
            })
        })
    })
});

const LIMITS = Object.freeze({
    tagline: 240,
    label: 80,
    url: 500,
    version: 40,
    title: 180,
    content: 30000
});

const cloneDefault = () => JSON.parse(JSON.stringify(DEFAULT_LEGAL_CONTENT));

const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

const normalizeText = (value, fallback = '') => {
    if (typeof value !== 'string') return fallback;
    return value.trim();
};

const normalizeContent = (value, fallback = '') => {
    if (typeof value !== 'string') return fallback;
    return value.replace(/\r\n/g, '\n').trim();
};

const normalizeVersion = (value, fallback = 'v1') => {
    if (typeof value !== 'string') return fallback;
    const normalized = value.trim();
    return normalized || fallback;
};

const isValidLegalUrl = (value) => {
    if (typeof value !== 'string') return false;
    const trimmed = value.trim();
    if (!trimmed) return false;
    if (trimmed.startsWith('/')) return true;
    return /^https:\/\/[^\s]+$/i.test(trimmed);
};

const normalizeFooterLang = (value, fallback) => {
    const source = isObject(value) ? value : {};
    return {
        tagline: normalizeText(source.tagline, fallback.tagline),
        privacyLabel: normalizeText(source.privacyLabel, fallback.privacyLabel),
        termsLabel: normalizeText(source.termsLabel, fallback.termsLabel)
    };
};

const normalizeDocLang = (value, fallback) => {
    const source = isObject(value) ? value : {};
    return {
        title: normalizeText(source.title, fallback.title),
        content: normalizeContent(source.content, fallback.content)
    };
};

const normalizeDocument = (value, fallback) => {
    const source = isObject(value) ? value : {};
    return {
        tr: normalizeDocLang(source.tr, fallback.tr),
        en: normalizeDocLang(source.en, fallback.en)
    };
};

const normalizeLegalContent = (value) => {
    const defaults = cloneDefault();
    const source = isObject(value) ? value : {};
    const footerSource = isObject(source.footer) ? source.footer : {};
    const versionsSource = isObject(source.versions) ? source.versions : {};
    const docsSource = isObject(source.documents) ? source.documents : {};

    const legacyPrivacyUrl = normalizeText(footerSource.privacyUrl, '');
    const legacyTermsUrl = normalizeText(footerSource.termsUrl, '');

    const urlsSource = isObject(footerSource.urls)
        ? footerSource.urls
        : {
            privacy: legacyPrivacyUrl || defaults.footer.urls.privacy,
            terms: legacyTermsUrl || defaults.footer.urls.terms
        };

    const privacyUrl = normalizeText(urlsSource.privacy, defaults.footer.urls.privacy);
    const termsUrl = normalizeText(urlsSource.terms, defaults.footer.urls.terms);

    // Backward compatibility: old single footer fields map to TR.
    const legacyTrFallback = {
        tagline: normalizeText(footerSource.tagline, defaults.footer.tr.tagline),
        privacyLabel: normalizeText(footerSource.privacyLabel, defaults.footer.tr.privacyLabel),
        termsLabel: normalizeText(footerSource.termsLabel, defaults.footer.tr.termsLabel)
    };

    const trSource = isObject(footerSource.tr) ? footerSource.tr : legacyTrFallback;
    const enSource = isObject(footerSource.en) ? footerSource.en : {};

    return {
        footer: {
            urls: {
                privacy: isValidLegalUrl(privacyUrl) ? privacyUrl : defaults.footer.urls.privacy,
                terms: isValidLegalUrl(termsUrl) ? termsUrl : defaults.footer.urls.terms
            },
            tr: normalizeFooterLang(trSource, defaults.footer.tr),
            en: normalizeFooterLang(enSource, defaults.footer.en)
        },
        versions: {
            terms: normalizeVersion(versionsSource.terms, defaults.versions.terms),
            privacy: normalizeVersion(versionsSource.privacy, defaults.versions.privacy)
        },
        documents: {
            privacy: normalizeDocument(docsSource.privacy, defaults.documents.privacy),
            terms: normalizeDocument(docsSource.terms, defaults.documents.terms)
        }
    };
};

const getLengthError = (value, max, label) => {
    if (typeof value !== 'string') return `${label} metin olmalidir.`;
    if (value.length > max) return `${label} en fazla ${max} karakter olabilir.`;
    return null;
};

const validateLegalContentPayload = (value) => {
    const source = isObject(value) ? value : null;
    if (!source) {
        return { ok: false, error: 'Gecersiz payload.' };
    }

    const rawChecks = [
        [source?.footer?.urls?.privacy || source?.footer?.privacyUrl, 'Gizlilik URL'],
        [source?.footer?.urls?.terms || source?.footer?.termsUrl, 'Sartlar URL'],
        [source?.footer?.tr?.tagline || source?.footer?.tagline, 'Footer TR slogan'],
        [source?.footer?.tr?.privacyLabel || source?.footer?.privacyLabel, 'Footer TR gizlilik etiketi'],
        [source?.footer?.tr?.termsLabel || source?.footer?.termsLabel, 'Footer TR sartlar etiketi'],
        [source?.footer?.en?.tagline, 'Footer EN tagline'],
        [source?.footer?.en?.privacyLabel, 'Footer EN privacy label'],
        [source?.footer?.en?.termsLabel, 'Footer EN terms label'],
        [source?.versions?.terms, 'Terms versiyon'],
        [source?.versions?.privacy, 'Privacy versiyon'],
        [source?.documents?.privacy?.tr?.title, 'Privacy TR baslik'],
        [source?.documents?.privacy?.tr?.content, 'Privacy TR icerik'],
        [source?.documents?.privacy?.en?.title, 'Privacy EN baslik'],
        [source?.documents?.privacy?.en?.content, 'Privacy EN icerik'],
        [source?.documents?.terms?.tr?.title, 'Terms TR baslik'],
        [source?.documents?.terms?.tr?.content, 'Terms TR icerik'],
        [source?.documents?.terms?.en?.title, 'Terms EN baslik'],
        [source?.documents?.terms?.en?.content, 'Terms EN icerik']
    ];

    for (const [rawValue, label] of rawChecks) {
        if (typeof rawValue !== 'string' || !rawValue.trim()) {
            return { ok: false, error: `${label} zorunludur.` };
        }
    }

    const normalized = normalizeLegalContent(value);

    if (!isValidLegalUrl(normalized.footer.urls.privacy)) {
        return { ok: false, error: 'Gizlilik URL gecersiz. Sadece /... veya https://... kabul edilir.' };
    }
    if (!isValidLegalUrl(normalized.footer.urls.terms)) {
        return { ok: false, error: 'Sartlar URL gecersiz. Sadece /... veya https://... kabul edilir.' };
    }

    const lengthChecks = [
        [normalized.footer.urls.privacy, LIMITS.url, 'Gizlilik URL'],
        [normalized.footer.urls.terms, LIMITS.url, 'Sartlar URL'],
        [normalized.footer.tr.tagline, LIMITS.tagline, 'Footer TR slogan'],
        [normalized.footer.tr.privacyLabel, LIMITS.label, 'Footer TR gizlilik etiketi'],
        [normalized.footer.tr.termsLabel, LIMITS.label, 'Footer TR sartlar etiketi'],
        [normalized.footer.en.tagline, LIMITS.tagline, 'Footer EN tagline'],
        [normalized.footer.en.privacyLabel, LIMITS.label, 'Footer EN privacy label'],
        [normalized.footer.en.termsLabel, LIMITS.label, 'Footer EN terms label'],
        [normalized.versions.terms, LIMITS.version, 'Terms versiyon'],
        [normalized.versions.privacy, LIMITS.version, 'Privacy versiyon'],
        [normalized.documents.privacy.tr.title, LIMITS.title, 'Privacy TR baslik'],
        [normalized.documents.privacy.tr.content, LIMITS.content, 'Privacy TR icerik'],
        [normalized.documents.privacy.en.title, LIMITS.title, 'Privacy EN baslik'],
        [normalized.documents.privacy.en.content, LIMITS.content, 'Privacy EN icerik'],
        [normalized.documents.terms.tr.title, LIMITS.title, 'Terms TR baslik'],
        [normalized.documents.terms.tr.content, LIMITS.content, 'Terms TR icerik'],
        [normalized.documents.terms.en.title, LIMITS.title, 'Terms EN baslik'],
        [normalized.documents.terms.en.content, LIMITS.content, 'Terms EN icerik']
    ];

    for (const [fieldValue, max, label] of lengthChecks) {
        const err = getLengthError(fieldValue, max, label);
        if (err) return { ok: false, error: err };
    }

    return { ok: true, value: normalized };
};

const fetchLegalSettings = async (pool) => {
    try {
        const result = await pool.query(
            'SELECT value, updated_at FROM app_settings WHERE key = $1 LIMIT 1',
            [LEGAL_SETTINGS_KEY]
        );
        if (!result.rows.length) {
            return { item: cloneDefault(), updatedAt: null };
        }
        return {
            item: normalizeLegalContent(result.rows[0].value),
            updatedAt: result.rows[0].updated_at || null
        };
    } catch (error) {
        // app_settings migration may not have completed yet on first boot.
        if (String(error?.code || '') === '42P01') {
            return { item: cloneDefault(), updatedAt: null };
        }
        throw error;
    }
};

const saveLegalSettings = async (pool, value) => {
    const normalized = normalizeLegalContent(value);
    const result = await pool.query(
        `INSERT INTO app_settings (key, value, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (key)
         DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
         RETURNING updated_at`,
        [LEGAL_SETTINGS_KEY, JSON.stringify(normalized)]
    );
    return result.rows[0]?.updated_at || null;
};

module.exports = {
    LEGAL_SETTINGS_KEY,
    DEFAULT_LEGAL_CONTENT,
    isValidLegalUrl,
    normalizeLegalContent,
    validateLegalContentPayload,
    fetchLegalSettings,
    saveLegalSettings
};
