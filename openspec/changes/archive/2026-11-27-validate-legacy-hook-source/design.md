## Decisions
Parse the submitted module in a bounded worker process. Examine syntax tree nodes so that comments and quoted strings are treated as data. Keep parsing and restricted-language validation separate. A parsed result alone cannot authorize execution or mark source as valid.
