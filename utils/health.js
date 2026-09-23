const createHealthState = () => ({ shuttingDown: false });

const createLivenessPayload = ({ release, healthState, now = () => new Date() }) => ({
    status: healthState.shuttingDown ? 'shutting_down' : 'live',
    service: release.service,
    appVersion: release.appVersion,
    commitSha: release.commitSha,
    environment: release.environment,
    timestamp: now().toISOString()
});

const createReadinessPayload = ({ release, database, healthState, now = () => new Date() }) => {
    const ready = !healthState.shuttingDown && database?.ok === true;
    return {
        status: ready ? 'ready' : 'not_ready',
        service: release.service,
        appVersion: release.appVersion,
        commitSha: release.commitSha,
        environment: release.environment,
        timestamp: now().toISOString(),
        checks: {
            database: {
                status: database?.ok ? 'ready' : 'not_ready',
                code: database?.code || (database?.ok ? 'OK' : 'DB_UNAVAILABLE'),
                schema: database?.schema || 'unknown',
                migrationHead: database?.migrationHead || null,
                expectedMigrationHead: database?.expectedMigrationHead || null
            }
        }
    };
};

module.exports = {
    createHealthState,
    createLivenessPayload,
    createReadinessPayload
};
