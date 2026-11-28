## Context

Both services can issue and rotate OAuth grants against one PostgreSQL primary. A successful rotation extends the existing refresh family.

## Decisions

Exercise a genuine authorization code with PKCE, offline access and a target resource. Check the chain of replacements and its client, scope and resource across a second rotation. After administrative revocation, check the OAuth error and committed records.

## Scope

The rehearsal covers drained writer switches for public and confidential clients.
