# Wave 04 Backup, Restore and Disaster Recovery Runbook

Last local verification: 2026-09-23. This document contains no credential values and does not authorize production backup, restore, cutover, restart or rotation.

## Identity and storage record

For every backup record the provider/project, database, `public` schema, migration head, source release, UTC capture time, PostgreSQL tool/server versions, archive SHA-256, encrypted storage location, access owner and retention decision. Keep the source and isolated restore target identities distinct.

The workspace artifact `backup/talkx_chatapp_reports_20260807.dump` is historical evidence only. Its old counts and restore result are not current production truth.

Read-only local verification on 2026-09-23 with `pg_restore 17.11`: 485262 bytes, 127 archive entries, SHA-256 `90bfa16377451a80cf15c5977de807ecc0e01634740a44ba203fd99ada55510d`. This proves only that the historical archive is listable and unchanged; it does not replace a current backup or isolated restore rehearsal.

## Backup procedure

1. Obtain explicit approval before reading live data into a new dump.
2. Confirm a direct PostgreSQL endpoint and read-only `current_schema()=public`; do not copy the connection string into notes or logs.
3. Confirm `pg_dump` major-version compatibility with the server.
4. Create a custom/compressed archive through an operator-controlled secret environment, never a command-line credential.
5. Calculate SHA-256 and run `npm run backup:verify -- <dump-path>`; record byte size, hash and archive entry count.
6. Encrypt before transfer when storage does not provide equivalent encryption. Restrict access to the named owner and record retention/expiry.
7. A listed archive is only a candidate backup until isolated restore succeeds.

## Isolated restore rehearsal

1. Use a new, explicitly identified temporary/staging database. Never point the rehearsal at production.
2. Restore with owner/privilege remapping appropriate to the target and single-transaction/exit-on-error where supported.
3. Verify `public` schema, extensions, roles/privileges, tables, columns, constraints, indexes, triggers and migration head.
4. Measure source counts immediately before the approved backup and target counts after restore for users/profiles/sessions, friendships, conversations/messages, reports, legal acceptances, push/support, audit and analytics classes.
5. Run a real Node `pg` read-only connection check against the direct endpoint and verify `current_schema()=public`.
6. Record restore duration, backup capture time and rehearsal completion time. RPO is the accepted source-data window; RTO is the measured restore plus verification/cutover window. Targets require owner approval and are not invented by this runbook.
7. Delete the temporary target only under its own explicit authorization and retention record.

## Cutover and rollback gate

The only valid order is: approved backup → archive verification → isolated restore and count parity → readiness → approved config change → approved restart/deploy → auth/WebSocket/user smoke → observation. Direct endpoint is preferred for TalkX because transaction/session behavior and `search_path=public` must be deterministic; a pooler is acceptable only after the same checks pass.

If schema, migration head, counts or readiness differ, do not cut over. Preserve evidence, keep the current production target unchanged and select a compatible forward-fix or verified prior artifact. Credential rotation and production restart always require explicit approval.
