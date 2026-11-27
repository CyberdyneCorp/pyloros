## Decisions

Use the same role inventory and permission lookup for operators and service clients. Resolve the client identity from the authenticated bearer on delegated routes. Validate the selected provider configuration before looking up roles. Only a configured runtime IAM chain supplies roles. A valid deployment-only provider leaves role membership in PostgreSQL.
