const BLACKLIST = [
    'admin', 'moderator', 'system', 'root',
    'amk', 'aq', 'oç', 'oc', 'orospu', 'sik', 'yarrak', 'piç', 'kahpe', 'sürtük', 'göt', 'mem', // Basic TR Profanity
    'fuck', 'shit', 'bitch', 'asshole', 'dick', 'pussy', // Basic EN Profanity
    'hitler', 'nazi', 'teror'
];

/**
 * Checks if a username is valid based on heuristics and blacklist.
 * @param {string} username 
 * @returns {object} { valid: boolean, reason: string|null }
 */
function validateUsername(username) {
    if (!username) return { valid: false, reason: "Kullanıcı adı boş olamaz." };

    // Normalize: Trim + Single Space
    const cleanName = username.trim().replace(/\s+/g, ' ');

    // 1. Length Check
    if (cleanName.length < 3 || cleanName.length > 15) {
        return { valid: false, reason: "Kullanıcı adı 3-15 karakter arasında olmalı." };
    }

    const lower = cleanName.toLowerCase();

    // "Compressed" version for sneaky checks (e.g. "a.m.k" -> "amk")
    const compressed = lower.replace(/[^a-z0-9]/g, '');

    // 2. Blacklist Check 
    // Check 1: Normal normalized version (contains word)
    // Check 2: Compressed version (contains sequence)
    for (const bad of BLACKLIST) {
        // Word boundary check for normal version is better but simple includes is safer for MVP security
        if (lower.includes(bad)) {
            return { valid: false, reason: "Uygunsuz ifadeler içeriyor." };
        }
        // Compressed check (catches 'a.m.k', 'a m k', 's.i.k')
        // Only if the bad word is > 2 chars to avoid false positives on 'oc' vs 'clock' if we strictly use compressed
        // For short words like 'oc', 'aq', we rely on direct match or strict bounds.
        if (bad.length > 2 && compressed.includes(bad)) {
            return { valid: false, reason: "Uygunsuz ifadeler içeriyor." };
        }
        // Strict compressed check for short words
        if (bad.length <= 2 && compressed === bad) {
            return { valid: false, reason: "Uygunsuz ifadeler içeriyor." };
        }
    }

    // 3. Phone Number Heuristic
    // Matches 8 or more consecutive digits, or pattern like 05xx xxx xx xx
    const digitCount = (lower.match(/\d/g) || []).length;
    if (digitCount >= 8) {
        return { valid: false, reason: "Telefon numarası veya ileti paylaşımı yasak." };
    }

    // 4. URL/Link Heuristic
    if (/(http|www|\.com|\.net|\.org|\.xyz|\.tr)/i.test(lower)) {
        return { valid: false, reason: "Link paylaşımı yasak." };
    }

    // 5. Spam/Repetition Check (e.g. aaaaaa)
    // Checks for characters repeated 4 or more times
    if (/(.)\1{3,}/.test(lower)) {
        return { valid: false, reason: "Tekrarlayan karakterler (spam) yasak." };
    }

    // 6. Character Set Limit (Optional but good)
    // Allow only Letters, Numbers, Space, Underscore, Dot, Dash
    // This rejects emojis or weird symbols if desired. For now allowing extended but warning:
    // User asked for "emojiler dahil sorun değil" in previous prompts, so we SKIP this check.

    return { valid: true };
}

module.exports = {
    validateUsername
};
