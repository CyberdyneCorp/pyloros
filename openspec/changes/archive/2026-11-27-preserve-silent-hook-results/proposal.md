## Why

Operators can distinguish missing output from a string in execution history. A successful component that emits zero bytes should have the same v1 representation during automatic and manual execution.

## What Changes

Record a null output for silent successes in v1 execution history, apply the v1 limit of 10,000 characters to successful manual and automatic output, and provide a buildable silent component for reviewed hook ports.

## Impact

Affects new automatic execution records. Historical rows keep their stored output.
