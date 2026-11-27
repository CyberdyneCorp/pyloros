## Approach

Use the existing first-party identity verifier before evaluating administrative access. Read current administrative grants on each request. Retrieve client metadata from the shared PostgreSQL schema and exclude credentials from response projections.

## Verification

Compare the same stored registrations through both backends, using the existing administrative clients as consumers. Cover authorization changes between requests, empty pages, invalid parameters and missing registrations.
