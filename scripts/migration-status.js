const { getDatabaseReadiness, closeDatabase } = require('../db');

(async () => {
    try {
        const state = await getDatabaseReadiness();
        console.log(JSON.stringify(state));
        process.exitCode = state.ok ? 0 : 1;
    } finally {
        await closeDatabase().catch(() => {});
    }
})();
