Use the service’s existing authenticated-encryption envelope with the subscription identifier as associated data. Keep the domain change and its audit record in one PostgreSQL transaction. Leave emitted event rows available to other subscriptions.

Rotations that read the same original credential can both complete. The last writer supplies the active credential and both writers retain the original for overlap. An audit failure deferred until commit rolls back the subscription change. Pyloros returns HTTP 500 in this case.
