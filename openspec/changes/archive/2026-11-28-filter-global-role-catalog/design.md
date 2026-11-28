## Decisions

Filter the organization delimiter before projecting membership counts or returning names for the capacity check. Keep the existing parser for client ownership and role-key validation. Preserve scoped-group handling when deleting a role.

## Verification

Exercise a database containing global and organization-specific groups, compare both backend orders and inspect the membership count subplan on PostgreSQL.
