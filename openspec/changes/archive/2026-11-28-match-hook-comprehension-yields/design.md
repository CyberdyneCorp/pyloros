## Decisions

Use the existing namespace stack. The first iterable runs in the enclosing scope. A nested lambda introduces its own function scope. Preserve restricted-language diagnostics before compiler context checks.
