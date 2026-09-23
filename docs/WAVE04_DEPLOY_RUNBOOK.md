# Wave 04 Deploy, Config and Rollback Runbook

Last local verification: 2026-09-23. Owner: TalkX release operator. Commands or external panel settings without newer dated evidence are stale.

## Ownership

| Surface | Canonical source | Release evidence |
|---|---|---|
| Backend | `chatapp-backend`, `origin/sale-release` for this release train | backend commit, package version, `/health/live`, `/health/ready` |
| Web client | `chatapp-frontend`, `origin/sale-release` | frontend commit and Vite artifact |
| Android | `chatapp-frontend/android` and synced frontend assets | version code/name, source commit, signed artifact hash |
| Plans/runbooks | `chatapp-backend/Plans` and this backend `docs` folder | backend commit |
| Database | configured PostgreSQL database, `public` schema, migration head | `/health/ready` plus operator evidence without credentials |

Workspace-root `Plans/` and `android/` are legacy/non-canonical and must not be release inputs.

## Safe configuration inventory

Values are never recorded here. The operator records only presence, owner, environment and dated panel evidence.

| Variable | Purpose | Required | Sensitive | Change effect |
|---|---|---:|---:|---|
| `DATABASE_URL` | PostgreSQL direct connection | yes | yes | restart/redeploy; readiness and migration gate required |
| `NODE_ENV` / `APP_ENV` | safe environment label | yes in hosted environments | no | restart/redeploy |
| `RENDER_GIT_COMMIT` | immutable backend commit identity | provider supplied | no | deploy supplied |
| `DB_POOL_MAX` | bounded pool size, 1–20 | no | no | restart/redeploy |
| `DB_CONNECT_TIMEOUT_MS` | connection timeout | no | no | restart/redeploy |
| `DB_QUERY_TIMEOUT_MS` | query timeout | no | no | restart/redeploy |
| `DB_STATEMENT_TIMEOUT_MS` | statement timeout | no | no | restart/redeploy |
| `DB_READINESS_TIMEOUT_MS` | readiness query bound | no | no | restart/redeploy |
| `PERF_MIN_PERCENTILE_SAMPLES` | low-confidence boundary | no | no | restart/redeploy |
| `PERF_P95_WARNING_MS` / `PERF_P95_CRITICAL_MS` | backend API threshold | no | no | restart/redeploy |
| `ALLOWED_ORIGINS` | HTTP/WebSocket origin policy | hosted | no | restart/redeploy and CORS smoke |
| Admin, Firebase and support credentials | existing provider access | environment dependent | yes | restart/redeploy and scoped smoke |

## Pre-deploy gate

1. Confirm clean backend/frontend repositories and exact target commits on the intended branch.
2. Run backend tests and syntax checks, frontend lint/build when frontend changed, and text-encoding validation.
3. Confirm the target migration head and read-only `current_schema()=public` result.
4. Confirm a current, encrypted, access-controlled backup and isolated restore rehearsal. A historical dump is not sufficient.
5. Record the rollback backend commit, frontend artifact and migration compatibility before deploy.
6. Compare required variable names with the target environment without copying values.
7. Obtain explicit user approval before production config, migration, restart or deploy.

## Deploy and observation

After approved deployment, verify in order:

1. `/health/live` answers independently of the database.
2. `/health/ready` is `ready`, reports `public`, and current/expected migration heads match.
3. Reported commit, version and environment match the target release evidence.
4. Register/login or an existing safe test account succeeds; no production data mutation beyond the approved smoke.
5. Authenticated WebSocket handshake and one critical user journey succeed.
6. Static routing, legal deep links, CORS and WebSocket origins work from the deployed client.
7. Observe error rate, readiness and logs for the recorded window; secrets, message bodies and raw SQL must not appear.

## Rollback

Rollback is to the recorded compatible commit/artifact, never an guessed branch tip. If the migration is not backward compatible, stop and use the documented forward-fix decision; do not run destructive SQL. Recheck liveness, readiness, release identity, auth, WebSocket and the critical user journey after rollback. Record time, release, impact, decision and evidence.
