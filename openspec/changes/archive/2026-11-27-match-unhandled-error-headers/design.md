## Decisions

Identify the generic unhandled-error response at its point of construction with a response extension. Middleware can then preserve handled error responses, including protocol-specific HTTP 500s, without inspecting a response body. A handler panic before response delivery returns the same generic error document.

## Verification

Compare an unhandled exception and a handled error with and without an Origin header, and with secure transport policy enabled. Check header presence, response body and status. Recheck the affected migration operations before marking them compatible.
