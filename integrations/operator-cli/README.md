# Relationship commands

The operator CLI build for Pyloros includes these commands under `cyberauth service rebac`. Configure the service client ID and client-secret file using the usual operator profile or service options. The commands request `rebac:manage` for writes and `rebac:check` for decisions by default. An explicit service scope overrides the default.

Use the collection model in the [API contract](../../openapi/rebac.yaml) as `model.json`. Set `USER_ID` to an existing account UUID.

```sh
cyberauth service rebac model --from-file model.json
cyberauth service rebac grant --object-type collection --object-id drafts \
  --relation member --subject-type user --subject-id "$USER_ID"
cyberauth service rebac check --object-type collection --object-id drafts \
  --permission read --user-id "$USER_ID"
cyberauth --dry-run service rebac revoke --object-type collection --object-id drafts \
  --relation member --subject-type user --subject-id "$USER_ID"
```

Omit `--dry-run` to perform the revocation. In unattended runs, supply `--yes` for destructive actions. Inspect the `allowed` boolean when scripting checks. Both allow and deny are successful evaluations. A failed request exits with a CLI error.

## Packaging

This directory contains the Rust command module for the shared operator CLI. The host build registers `Command` under `service rebac`, adds `OPS` to its operation registry and merges the [OpenAPI paths and components](../../openapi/rebac.yaml) into its snapshot. Before token acquisition it selects `Command::scope()` when the operator supplied no scopes. It uses `Command::mutating()` for offline mutation previews and passes its request context and in-memory service token to `Command::run`.
