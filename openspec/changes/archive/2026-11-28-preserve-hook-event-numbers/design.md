## Decisions

Validate the event once per admission boundary and pass the original bytes to the guest. Apply the same JSON syntax, string, nesting and size checks to events containing large numbers. The guest decides how to interpret each field.
