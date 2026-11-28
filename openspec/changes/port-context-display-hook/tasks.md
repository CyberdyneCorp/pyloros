## Compare and implement

- [x] Compare real manual source execution for empty, nested, repeated-name and oversized-output inputs.
- [x] Compare source registration history with a component that echoes the delivered event, with personal fields enabled and disabled.
- [x] Preserve registration ordering and delivery-time redaction, including existing pending rows and permission changes.
- [x] Implement the ordered renderer, package the guest with a just recipe, and exercise it in worker CI.
- [x] Compare manual and automated history from both backends, including private-field withdrawal before worker execution and the Unicode output boundary.
- [x] Verify dense integer, fixed-point decimal, simple string and nested array output against the source under the existing worker budget.
- [ ] Reconcile remaining budget failures on dense arrays of objects, quoted strings and exponent-form numbers.
