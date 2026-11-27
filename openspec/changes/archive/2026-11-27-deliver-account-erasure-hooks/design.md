## Decisions
Keep the erased UUID in the event payload, without a foreign key back to the removed user. All other pending subject deliveries retain their cascading foreign key. Sweep execution history after user deletion so that a worker finishing an older delivery during erasure cannot leave personal data behind.
