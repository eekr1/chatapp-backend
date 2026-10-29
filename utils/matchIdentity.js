// A search owns an immutable public identity. Never accept profile fields from a socket.
const normalizeIdentityMode = (value) => ['anon', 'profile'].includes(value) ? value : 'legacy';
const safeAvatar = (value) => /^\/avatars\/avatar-[1-6]\.svg$/.test(String(value || '')) ? value : null;
const publicMatchIdentity = (participant = {}) => {
    const mode = normalizeIdentityMode(participant.identityMode);
    if (mode === 'anon') return { peerIdentityMode: 'anon', peerNickname: 'Anonymous', peerUsername: null, peerAvatar: null };
    const profile = participant.publicProfile || {};
    return {
        peerIdentityMode: mode,
        peerNickname: mode === 'profile' ? String(profile.displayName || 'TalkX').slice(0, 80) : participant.nickname || null,
        peerUsername: mode === 'profile' ? profile.username || null : participant.username || null,
        peerAvatar: mode === 'profile' ? safeAvatar(profile.avatar) : null
    };
};
const resolveSearchIdentity = async ({ pool, userId, mode, legacyNickname, legacyUsername }) => {
    const identityMode = normalizeIdentityMode(mode);
    if (identityMode !== 'profile') return { identityMode, publicProfile: null, nickname: legacyNickname, username: legacyUsername };
    const result = await pool.query('SELECT u.username, p.display_name, p.avatar_url FROM users u LEFT JOIN profiles p ON p.user_id = u.id WHERE u.id = $1 AND u.status = $2', [userId, 'active']);
    const row = result.rows[0];
    if (!row) throw new Error('PROFILE_UNAVAILABLE');
    return { identityMode, publicProfile: { username: row.username, displayName: row.display_name || row.username, avatar: safeAvatar(row.avatar_url) || '/avatars/avatar-1.svg' } };
};
module.exports = { normalizeIdentityMode, safeAvatar, publicMatchIdentity, resolveSearchIdentity };
