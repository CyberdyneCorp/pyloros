## Approach

Reuse password registration validation, wallet encryption, hashing and insertion. An operator-created account starts with a verified email. Commit its authentication event, administrator audit entry and matching webhook deliveries with the user. Preserve the registration hook coexistence behavior until the shared dispatcher supports the event.
