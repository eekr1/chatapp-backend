# TalkX Local IP-to-Country Database

This directory contains the generated country-only lookup files used by `ip-location-api`.

- Source dataset: [`sapics/ip-location-db` — `user-country`](https://github.com/sapics/ip-location-db)
- Dataset license: Open Data Commons Public Domain Dedication and License 1.0 (PDDL)
- Generated for TalkX: 2026-09-28
- Included fields: ISO 3166-1 alpha-2 country code only
- Runtime network behavior: none

The dataset is committed intentionally so backend startup and user authentication never depend on a geo provider or a database download. Refresh it deliberately with:

```powershell
npm.cmd run geo:country:update
```

After an update, run the backend test suite and review the six files under `g/` before committing.
