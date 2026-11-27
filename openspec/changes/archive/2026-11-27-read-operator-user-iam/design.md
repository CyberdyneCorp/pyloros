## Decisions

Reuse the existing operator gate and IAM provider selection. Derive the assignment view from the same stored links that operator mutations update. Keep the token metadata view independent from the IAM assignment view so each follows its own provider and error semantics.

## Verification

Use the unchanged user administration page and CLI. Compare empty and populated responses, expired sessions, missing users, historical metadata, chain identity lookups, unavailable providers and switches between providers.
