Authenticate an administrator before validating report parameters. Aggregate each report in PostgreSQL so the server can return a bounded response even with a large session history. Preserve the registration lookback, identity grouping and session activity definitions used by existing callers.

For migration, set `PYLOROS_REGISTRATION_TIME_ZONE` to the result of `SHOW TimeZone` on a reference application connection. The registration report uses that zone for calendar labels. Its rolling cutoff is independent of the calendar zone. If unset, the report uses the Rust connection’s session time zone.

Overview and activity capture a common time boundary for their respective windows. Counts are read in report order at PostgreSQL’s read-committed isolation level. A commit between counts can become visible in the later counter. Authentication method totals use the account count taken before the identity breakdown.
