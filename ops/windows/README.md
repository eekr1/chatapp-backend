# Windows migration preparation

The backend remains on Render until cutover is verified. Do not start two production matching instances.

`Install.ps1 -SecretSource <Render-export-path>` installs a stopped/manual LocalService service and immutable committed source. Production credentials stay outside Git. `launch.cjs` binds localhost and trusts Cloudflare client IP only for a loopback peer.

Before starting: current encrypted backup and isolated restore rehearsal, matching production migration checksums, working named Tunnel, DNS inventory, and an agreed old-client route are required. This preparation does not create Tunnel credentials, change DNS, schedule automatic deploys, or stop Render.

After cutover, `Deploy.ps1 -Commit <prepared-sha> -ExternalUrl https://api.talkx.chat` switches prepared releases and rolls back on local readiness/CORS/WS or external smoke failure. It does not roll back database schemas. Before using for upgrades, verify migration compatibility and prepare previous release.

`TalkXDeploy` is a LocalService poller. Every two minutes it checks the current `sale-release` head and a successful GitHub-hosted push CI run for that exact SHA, newer than its activation timestamp. It checks out that commit, installs locked production dependencies, verifies database readiness without migrations, switches the stopped service, and checks local readiness plus external HTTPS/CORS/WS. Failed candidates remain for operator inspection. No self-hosted Actions runner is registered on the personal PC.

The poller requires an already healthy current backend and cannot perform the initial cutover. Credentials remain in `C:\TalkX\secrets`; its writable locations are releases, deploy state, logs, and the active-release pointer. Its service control permission applies only to TalkXBackend. Upgrades requiring migrations are stopped by candidate preflight.

Production endpoint: `https://api.talkx.chat` (WebSocket `wss://api.talkx.chat`). Frontend stays on Render. Push to `sale-release` after local checks; successful GitHub CI makes the exact branch head eligible for the PC poller. A PC shutdown takes the backend offline; Windows service automatic start resumes it after boot. Do not resume the old Render matching backend concurrently.

## Private repository deployment (poller authentication)

When `eekr1/chatapp-backend` becomes private, anonymous API and `git clone` access stop working. The poller (`TalkXDeploy`) runs anonymously until `C:\TalkX\secrets\github-readonly.token` exists; the token is picked up on service start.

Setup (done by Enis, credentials never leave the PC):

1. GitHub → Settings → Developer settings → Fine-grained personal access tokens. Repository access: only `eekr1/chatapp-backend`. Permissions: `Contents: Read-only`, `Actions: Read-only`, `Metadata: Read-only` (Metadata is mandatory and preselected). Set an expiry you will remember to rotate.
2. Write the token itself as a single line into `C:\TalkX\secrets\github-readonly.token` (surrounding whitespace is trimmed). Do not paste it into chats, tickets, screenshots or logs.
3. Restart the poller: `Restart-Service TalkXDeploy` (admin PowerShell).

From then on, API calls carry `Authorization: Bearer <token>` and `git clone` carries an `http.extraHeader` (`Authorization: Basic base64("x-access-token:<token>")`) passed through process environment variables, never command-line arguments. Neither the token nor its encoded form is ever written to logs. Deleting the token file and restarting TalkXDeploy restores the old anonymous behavior (works again once the repo is public). If the token leaks, revoke it in GitHub, delete the file, and repeat the setup with a new token.

## Nightly encrypted database backup

`Register-BackupTask.ps1` (elevated PowerShell; safe to re-run) copies `Backup.ps1` + `backup.cjs` to `C:\TalkX\ops\windows` and registers scheduled task `TalkXNightlyBackup`: daily 04:00 local time, running as SYSTEM, 2h execution limit, missed starts are caught up. Manual run: `powershell -NoProfile -ExecutionPolicy Bypass -File C:\TalkX\ops\windows\Backup.ps1`.

Each run: `pg_dump --format=custom` of the database from `DATABASE_URL` in `C:\TalkX\secrets\backend.env` (credentials travel only via libpq environment variables, never command lines or logs) → verification of the plaintext dump with the active release's `scripts/verify-backup.js` (SHA-256 + `pg_restore --list`) → AES-256-GCM encryption (fresh random 32-byte key written to `C:\TalkX\secrets\backup-<UTC-stamp>.key`; base64 IV/authTag/ciphertext wrapped as JSON, matching the existing `*.dump.aes.json` convention) → `C:\TalkX\backups\nightly\talkx-db-<UTC-stamp>.dump.aes.json` → nightly archives older than 14 days are deleted together with their paired keys. Every result line lands in `C:\TalkX\logs\backup-<date>.log`. `pg_dump`/`pg_restore` resolve from `PG_DUMP_BIN`/`PG_RESTORE_BIN` if set, else `C:\TalkX\bin`, else `PATH`.

Restore (isolated target only — see `docs/WAVE04_BACKUP_RESTORE_RUNBOOK.md`; never restore over production):

1. Decrypt: `node C:\TalkX\ops\windows\backup.cjs --decrypt --archive C:\TalkX\backups\nightly\<file>.dump.aes.json --key C:\TalkX\secrets\backup-<stamp>.key --out C:\TalkX\backups\restore\<file>.dump` (GCM auth tag failure means wrong key or corrupted archive).
2. Verify: from the active release, `npm run backup:verify -- C:\TalkX\backups\restore\<file>.dump <sha256 from the envelope>`.
3. `pg_restore` into a fresh staging database with owner/privilege remapping; confirm schema, migration head and row-class counts against the runbook before any cutover decision.
