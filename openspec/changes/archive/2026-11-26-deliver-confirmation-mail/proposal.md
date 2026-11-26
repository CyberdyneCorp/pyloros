## Why
The browser must receive the emailed confirmation link through the configured provider before login can continue.

## What Changes
Deliver a plain-text message to a TLS-authenticated SMTP relay, and provide a process-local mock outbox for development.

## Capabilities
### Modified Capabilities
- mfa-challenges
