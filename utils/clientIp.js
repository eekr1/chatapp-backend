const net = require('net');

const normalizeIp = (value) => {
    let ip = String(value || '').trim();
    if (!ip) return null;
    if (ip.startsWith('[') && ip.includes(']')) ip = ip.slice(1, ip.indexOf(']'));
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(ip)) ip = ip.slice(0, ip.lastIndexOf(':'));
    if (ip.includes('%')) ip = ip.slice(0, ip.indexOf('%'));
    return net.isIP(ip) ? ip : null;
};

const getTrustedProxyHops = (env = process.env) => {
    const fallback = env.NODE_ENV === 'production' ? 1 : 0;
    const parsed = Number(env.TRUST_PROXY_HOPS);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(0, Math.min(5, Math.floor(parsed)));
};

const resolveClientIp = (req, env = process.env) => {
    const socketIp = normalizeIp(req?.socket?.remoteAddress || req?.connection?.remoteAddress || req?.ip);
    const hops = getTrustedProxyHops(env);
    if (hops <= 0) return socketIp;
    const forwarded = String(req?.headers?.['x-forwarded-for'] || '')
        .split(',')
        .map(normalizeIp)
        .filter(Boolean);
    if (!forwarded.length) return socketIp;
    return forwarded[Math.max(0, forwarded.length - hops)] || socketIp;
};

module.exports = { getTrustedProxyHops, normalizeIp, resolveClientIp };
