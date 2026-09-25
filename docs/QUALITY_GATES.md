# TalkX Backend Quality Gates

Wave 17 Sale Release minimum gate is `npm run quality:all`. It runs fail-closed policy self-tests, automatic JavaScript syntax discovery, all backend core tests, the focused auth/session/two-client/match/reconnect/duplicate suite and a high-severity production dependency audit.

The runner fails when syntax discovery finds no JavaScript, a suite manifest finds no files or no `test(...)` declarations, or live database/provider variables are present. These Wave 17 suites use deterministic in-memory fakes and synthetic fixtures; they never connect to PostgreSQL, Firebase, Brevo or another live destination.

`Backend quality` is the stable GitHub check name. The workflow has read-only repository contents permission, uses lockfile installation, pins external actions to immutable commit SHAs, has no deploy job and receives no application secrets. A failed, cancelled or missing job is not converted to success; there is no automatic retry or `continue-on-error`.

Audit policy blocks high and critical production findings. The current eight moderate findings trace to the `firebase-admin`/Google dependency chain and `uuid` advisory `GHSA-w5hq-g745-h8pq`; the available automatic fix is breaking. They remain visible and unaccepted for release-owner review by Wave 19 or 2026-10-25, whichever comes first. Wave 17 does not perform a breaking dependency upgrade.

Ephemeral PostgreSQL matrices, browser/device E2E, branch-protection settings and deploy enforcement remain explicit external/manual gates. Android version, signing, bundle, device parity and store operations belong to Wave 18 and are not performed here.
