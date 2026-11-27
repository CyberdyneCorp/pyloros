## Why

The SMTP library applies a shorter local-part limit than the account API. During migration this prevents some existing users from registering, recovering an account or receiving verification mail through either writer.

## What Changes

Validate local-part syntax, Unicode safety and whole-address limits at input. Use the same checked recipient rules when delivering mail to a long account address.

## Impact

Account lookup, signup and outbound account mail must agree on which long addresses work. Relay acceptance remains observable at delivery time.
