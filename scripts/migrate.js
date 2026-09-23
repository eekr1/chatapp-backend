const { runMigrations, closeDatabase } = require('../db');

(async () => {
    try {
        const state = await runMigrations();
        console.log(JSON.stringify({
            status: state.ok ? 'current' : 'not_current',
            currentHead: state.currentHead,
            expectedHead: state.expectedHead
        }));
        process.exitCode = state.ok ? 0 : 1;
    } catch (error) {
        console.error(JSON.stringify({
            status: 'failed',
            errorCode: error?.code || 'MIGRATION_FAILED',
            version: error?.version || null
        }));
        process.exitCode = 1;
    } finally {
        await closeDatabase().catch(() => {});
    }
})();
