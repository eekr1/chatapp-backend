# TalkX Global Compliance Matrix — Wave 01

Last repository verification: 2026-09-23

This matrix separates repository evidence from evidence that requires Google Play Console access or qualified human review. It is an operational checkpoint, not legal advice, and it does not authorize a store, legal-content, configuration, database, or production change.

## Product identity baseline

- TalkX is a global random one-on-one chat product.
- Account holders are anonymous to the person they are matched with; TalkX still processes service data under its Privacy Policy.
- Anonymous chat messages are temporary and photos are disabled in that mode.
- Users may become friends and continue with persistent message history and controlled single-use photos.
- The product is not silently repositioned as 18+ and is not reduced to a single country.
- Canonical repository copy is mirrored in the Web/Android client and `chatapp-frontend/docs/TALKX_STORE_PRODUCT_COPY.md`. Live store copy remains externally controlled.

## Evidence and decision matrix

| Area | Current repository evidence | External or human evidence required | Owner | Status | Last verified |
|---|---|---|---|---|---|
| Product promise | TR/EN Splash and Home copy, web manifest, store-copy source | Compare the live Google Play listing with the repository source | Product owner | Repo verified / external deferred | 2026-09-23 |
| Account-based anonymity | Client copy explicitly separates user-to-user anonymity from service processing | Human privacy review of the wording against current production data flows | Product + privacy owner | Repo verified / human review deferred | 2026-09-23 |
| Anonymous vs friend retention | Client states temporary anonymous messages, persistent friend history, and single-use photos; current backend keeps anonymous room text ephemeral and persists direct messages | Human review against the final retention schedule and live privacy text | Backend owner + privacy owner | Code/copy verified / policy review deferred | 2026-09-23 |
| Target audience | No repository decision silently changes TalkX to an 18+ product | Google Play Console Target audience and content settings screenshots/answers | Store owner | Deferred to Wave 19 | 2026-09-23 |
| Content rating | Random/anonymous chat, user-generated communication, report/block, and controlled photo behavior are documented in canonical plans | Complete and capture the live Play content-rating questionnaire without understating features | Store owner | Deferred to Wave 19 | 2026-09-23 |
| Data Safety | Auth, sessions, profiles, IP/user-agent snapshots, messages, support reports/media, push devices/logs, legal acceptance, analytics, and moderation data exist in code/schema | Reconcile every live Data Safety answer with production data flows, SDKs, retention, encryption, and deletion behavior | Privacy owner + Android owner | Deferred to Wave 19 | 2026-09-23 |
| Country/region distribution | Product baseline remains global; no code change restricts regions | Record current Play country/region distribution and any age/store restriction with user impact | Store owner | Deferred to Wave 19 | 2026-09-23 |
| CSAE/CSAM policy source | Child Safety is a named legal surface in the product/legal model | Qualified human validates policy text, applicable reporting duties, preservation rules, and authority channels | Child-safety owner | Missing external evidence | 2026-09-23 |
| Child-safety operations | Reporting, blocking, bans, support reports, and admin audit surfaces exist | Name an accountable owner and backup; document triage severity, response target, escalation, evidence preservation, and after-hours path | Child-safety owner | Owner and escalation not yet verified | 2026-09-23 |
| Authority reporting | No verified authority-reporting runbook is stored in the repository | Qualified human records country-appropriate authority/NCMEC-equivalent path, thresholds, approvals, and case evidence | Legal/child-safety owner | Missing external evidence | 2026-09-23 |
| Child-safety contact | No verified public or operational contact is established by code evidence | Verify monitored contact address, accountable person, backup, access controls, and response coverage | Product owner | Missing external evidence | 2026-09-23 |
| Terms — TR/EN | Versioned Terms content is served by the existing legal API and client surface | Qualified bilingual/legal human reviews both live-language versions and records version/hash/date | Legal owner | Human review deferred | 2026-09-23 |
| Privacy — TR/EN | Versioned Privacy content is served by the existing legal API and client surface | Qualified bilingual/privacy human reviews both live-language versions against current processing | Privacy owner | Human review deferred | 2026-09-23 |
| Community Guidelines — TR/EN | Community Guidelines is a named public legal surface | Qualified bilingual/trust human verifies both live versions and moderation alignment | Trust owner | Human review deferred | 2026-09-23 |
| Child Safety — TR/EN | Child Safety is a named public legal surface | Qualified bilingual/child-safety human verifies both live versions and operational accuracy | Child-safety owner | Human review deferred | 2026-09-23 |
| Web/Android parity | Android canonical source is `chatapp-frontend/android`; Capacitor bundles the same web client | Real-device screenshot and behavior comparison, including small screen and accessibility | Android owner | Automated asset check in Wave 01 / manual deferred | 2026-09-23 |

## Required Wave 19 evidence packet

1. Timestamped Play Console captures for Target audience, content rating, Data Safety, and country/region distribution.
2. Live store copy compared line-by-line with `chatapp-frontend/docs/TALKX_STORE_PRODUCT_COPY.md`.
3. Named child-safety owner and backup, monitored contact, escalation tree, response targets, and authority-reporting runbook.
4. Qualified human review records for Terms, Privacy, Community Guidelines, and Child Safety in TR and EN, including version/hash/date.
5. Web and real Android device screenshots showing the same product meaning without layout regression.

Until those items exist, the corresponding C-COMP-001 acceptance criteria remain open. No live console or legal publication action was performed in Wave 01.
