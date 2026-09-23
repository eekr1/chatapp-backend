# Wave 06 Data Lifecycle and Privacy Checkpoint

This runbook records the Sale Release engineering boundary. It does not authorize a production query, migration, backfill, retention execute, account deletion, backup restore, secret change, deploy, legal publication, or provider configuration change.

## Implemented core

- `talkx-data-policy-v1` is the machine-readable data-class registry. Structural validation rejects missing keys and `TBD`; release validation remains fail-closed while named human reviews are pending.
- Migration `003` is additive: canonical `user_match_country`, deletion step ledger and erasure journal, plus support record/delivery/idempotency fields.
- Country candidates use a strict ISO alpha-2 allowlist. Unknown, fuzzy, local/private and unresolved values are unavailable; conflicts are disputed; a newer canonical row wins over a legacy candidate.
- `/api/me/match-country` is read-only and returns only the authenticated account's effective country. It exposes no selector, queue scope, raw IP, GPS, city, or provider payload.
- A deletion request returns a stable receipt, revokes sessions, marks the account pending and broadcasts user-scoped runtime termination. Completion uses per-class steps, pseudonymizes retained rows, produces a minimum HMAC subject reference and writes an erasure journal entry.
- Destructive admin completion requires current Basic re-auth, the exact confirmation phrase, current policy version and a configured erasure HMAC key. Missing key fails closed.
- Support retries may carry a bounded `submissionId`; the database record state and Brevo delivery state are separate.

## Production and legal gates

The following stay closed until explicit authorization and evidence are supplied:

- Run migration `003` against production or inspect/export production PII.
- Configure or rotate `ERASURE_HMAC_KEY`; export/sign/encrypt the journal artifact.
- Execute a retention batch, deletion, legacy country backfill, backup restore or erasure replay.
- Assert Firebase, Brevo, geo-provider, hosting/database or backup regions. Those rows remain `verification_required`.
- Publish Privacy, Terms, Data Safety or store changes. Product/privacy/legal owner review is deferred to Checkpoint A/Wave 19.

## Restore gate

Before any restored database can receive traffic, verify migration head, validate the independently stored erasure artifact, replay completed subject references idempotently, and prove that sessions, push tokens, canonical country rows and direct identifiers are absent. Missing/invalid artifacts or policy-version drift block cutover.

## Deferred manual QA

- Synthetic full user graph in isolated staging, two WebSocket clients, duplicate requests and mid-step retry.
- Masking/reveal/accessibility review in admin UI and web/Android deletion copy.
- Processor enablement/region evidence and row-by-row privacy/legal approval.
- Isolated old-backup restore plus signed journal replay rehearsal.

Wave 07 search lifecycle and Wave 08 queue scope/selector/fallback are not implemented here.
