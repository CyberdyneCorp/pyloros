## Why
Cookie-authenticated mutations need request-origin and CSRF checks before they reach an application handler.

## What Changes
Validate the request origin and compare the CSRF cookie with the submitted header on browser writes. Use the live browser origin registry for both CSRF and CORS.

## Impact
HTTP middleware and browser client configuration.
