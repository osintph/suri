# Known gaps and planned improvements

## web.sqli.timing: no SQLite sleep payload

SQLite does not expose a sleep/delay function in its SQL dialect. Suri's
timing-based SQLi payloads target MySQL (`SLEEP()`), PostgreSQL
(`pg_sleep()`), and MSSQL (`WAITFOR DELAY`). None of these produce a
measurable delay against a SQLite backend, so `web.sqli.time` will not
fire on SQLite-backed endpoints regardless of whether the parameter is
injectable.

Error-based detection (`web.sqli.error`) is unaffected and does cover
SQLite (added in v0.1 session 6.5).

Planned: add a SQLite-specific timing primitive (e.g. a heavy recursive
CTE or a `randomblob()` call sized to burn several seconds of CPU) as an
optional payload in `payloads.toml` with a `database_hint` field. The
check would probe with the hint-matched payload first when a SQLite error
has already been confirmed on the same parameter.
