# TalkX Automatic Match Country Pipeline

## Purpose

Automatically resolve every active profile's current connection country and maintain the canonical `user_match_country` record used by country-scoped matchmaking.

```text
register / login / authenticated WebSocket
                    |
                    v
 trusted proxy-aware client IP resolver
                    |
                    v
 local country-only IP database (no IP egress)
                    |
                    v
 ISO 3166-1 alpha-2 validation (TR, DE, US...)
                    |
                    v
 user_match_country UPSERT
                    |
                    v
 welcome.matchScopes.countryAvailable = true
                    |
                    v
 match:country:<ISO> queue
```

## Coverage

- Existing active profiles: a startup worker processes up to 100 due records per batch and continues every five seconds until the backlog is empty.
- New profiles: registration schedules a non-blocking country write from the trusted request IP.
- Returning profiles: login schedules a refresh, and authenticated WebSocket setup performs the authoritative refresh before sending `welcome`.
- Profile API: `GET /me/match-country` self-heals the canonical record before returning it.

## Safety properties

- The client never submits a country code.
- User IP addresses never leave the TalkX backend for matchmaking resolution.
- `user_match_country` stores only country code, source, status, timestamps and policy metadata; it does not store raw IP.
- Private, local, missing or unresolved IPs never erase an existing verified country.
- Lookup failure never blocks registration, login or WebSocket authentication; Global remains available.
- The local database is committed with the backend, so runtime startup performs no download.

## Configuration

- `TRUST_PROXY_HOPS`: trusted reverse-proxy count. Production default is `1`; local development default is `0`.
- `MATCH_COUNTRY_REFRESH_MS`: same-country canonical record refresh period; default 7 days.
- `MATCH_COUNTRY_RETRY_MS`: unavailable record retry period; default 6 hours.
- `MATCH_COUNTRY_BACKFILL_BATCH_SIZE`: startup batch size; default 100, maximum 200.
- `MATCH_COUNTRY_BACKFILL_BATCH_DELAY_MS`: delay while backlog remains; default 5 seconds.
- `MATCH_COUNTRY_BACKFILL_IDLE_MS`: delay after backlog is empty; default 6 hours.

## Operational checks

```sql
SELECT status, confidence, COUNT(*)
FROM user_match_country
GROUP BY status, confidence
ORDER BY status, confidence;
```

```sql
SELECT country_code, COUNT(*)
FROM user_match_country
WHERE status = 'eligible'
GROUP BY country_code
ORDER BY COUNT(*) DESC;
```

Low-volume country reporting must continue to use the existing privacy suppression rules. IP-country data describes the connection location, not nationality or permanent residence. VPN/proxy users may resolve to the network exit country.
