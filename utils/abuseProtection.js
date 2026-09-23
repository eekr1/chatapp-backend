const crypto = require('crypto');

const hashKey = (kind, value) => crypto.createHash('sha256')
    .update(`${kind}:${String(value || 'unknown')}`)
    .digest('hex')
    .slice(0, 24);

const resolvePeerAddress = (req) => String(req?.socket?.remoteAddress || req?.ip || 'unknown').trim().slice(0, 120);

class BoundedRateLimiter {
    constructor({ windowMs, max, maxKeys = 10000, now = () => Date.now() }) {
        this.windowMs = windowMs;
        this.max = max;
        this.maxKeys = maxKeys;
        this.now = now;
        this.buckets = new Map();
    }

    consume(key, cost = 1) {
        const now = this.now();
        this.sweep(now);
        let bucket = this.buckets.get(key);
        if (!bucket || bucket.resetAt <= now) bucket = { used: 0, resetAt: now + this.windowMs };
        bucket.used += Math.max(1, Number(cost) || 1);
        this.buckets.delete(key);
        this.buckets.set(key, bucket);
        while (this.buckets.size > this.maxKeys) this.buckets.delete(this.buckets.keys().next().value);
        return {
            allowed: bucket.used <= this.max,
            remaining: Math.max(0, this.max - bucket.used),
            retryAfterMs: Math.max(0, bucket.resetAt - now),
            resetAt: bucket.resetAt
        };
    }

    sweep(now = this.now()) {
        for (const [key, bucket] of this.buckets) {
            if (bucket.resetAt <= now) this.buckets.delete(key);
        }
    }
}

const actorKeys = ({ req, userId, deviceId, connectionId }) => {
    const keys = [`ip:${hashKey('ip', resolvePeerAddress(req))}`];
    if (userId) keys.push(`user:${hashKey('user', userId)}`);
    if (deviceId) keys.push(`device:${hashKey('device', deviceId)}`);
    if (connectionId) keys.push(`connection:${hashKey('connection', connectionId)}`);
    return keys;
};

module.exports = { BoundedRateLimiter, actorKeys, hashKey, resolvePeerAddress };
