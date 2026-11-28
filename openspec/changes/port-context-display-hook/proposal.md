## Why

The console starts a new hook with a script that prints its context. Operators can see dictionary order, quoting and numeric formatting in execution history. A JSON echo component produces different output for the same event.

## What Changes

Provide a Rust WebAssembly guest for this script and preserve registration field order when delivering events from the PostgreSQL queue.

## Impact

Applies to the guest examples, their build recipe and registration event delivery. The existing console continues to create its original source definition. Operators select the reviewed component using the existing source-digest binding.
