## ADDED Requirements

### Requirement: Validate yield expressions in comprehension scopes
The source validator SHALL report a compiler context error for a permitted yield expression directly in the implicit scope of a comprehension. It SHALL evaluate the first iterable in the enclosing scope and a nested lambda body in its own function scope.

#### Scenario: Yield in a comprehension result
- **WHEN** an operator validates a function with a parenthesized yield as the result expression of a list comprehension
- **THEN** return HTTP 500

#### Scenario: Yield supplies the first iterable
- **WHEN** an operator validates a function with a yield supplying the first iterable of an otherwise valid comprehension
- **THEN** return a positive validation result

#### Scenario: Generator contains an unparenthesized yield result
- **WHEN** a function contains a generator expression beginning with a bare yield followed by a comprehension clause
- **THEN** report invalid syntax in the HTTP 200 validation result
