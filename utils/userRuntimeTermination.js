const listeners = new Set();

const onUserRuntimeTermination = (listener) => {
    if (typeof listener !== 'function') throw new TypeError('listener must be a function');
    listeners.add(listener);
    return () => listeners.delete(listener);
};

const requestUserRuntimeTermination = async ({ userId, reason, requestId }) => {
    const normalized = {
        userId: String(userId || '').trim(),
        reason: String(reason || 'account_deletion_requested').trim(),
        requestId: requestId ? String(requestId) : null
    };
    if (!normalized.userId) throw new TypeError('userId is required');
    const results = await Promise.allSettled([...listeners].map((listener) => listener(normalized)));
    return {
        listenerCount: results.length,
        acknowledged: results.filter((item) => item.status === 'fulfilled').length,
        failed: results.filter((item) => item.status === 'rejected').length
    };
};

module.exports = { onUserRuntimeTermination, requestUserRuntimeTermination };
