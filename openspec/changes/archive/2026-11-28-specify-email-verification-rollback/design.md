## Decision

Use the existing PostgreSQL transaction to consume the code, verify the account, apply eligible domain membership and record success. Emit the successful response after commit. An explicit rejection leaves the committed state available for a retry through either writer.
