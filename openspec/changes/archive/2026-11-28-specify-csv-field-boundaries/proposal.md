## Why
Operators exporting a spreadsheet need to know whether long fields, including ignored columns, can prevent an entire import.

## What Changes
Specify the field-size boundary for uploaded CSV headers and data. Cover the boundary and whole-file rejection in parser regression tests.

## Capabilities
### Modified Capabilities
- admin-user-import

## Impact
The bulk-import contract and its verification.
