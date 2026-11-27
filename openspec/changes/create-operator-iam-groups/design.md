## Decisions

Validate operator authority and the submitted group fields. Reserve client-role names for the client-role API. On PostgreSQL, commit group creation and its operator audit together. Verify the returned identifier through the group inventory on both services.

## Verification

Compare validation, namespace boundaries, duplicate names, audit rollback, provider switching and concurrent requests. Exercise the unchanged console and CLI.
