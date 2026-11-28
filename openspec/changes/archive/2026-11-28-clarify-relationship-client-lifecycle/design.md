## Decisions

Bind graph ownership to the registration UUID. The operator deletion endpoint updates the active flag on the existing registration. A foreign-key cascade removes graph data when the backing row is deleted. Use two readers on the same primary to verify committed state and a separate client with identical object identifiers to check isolation.
