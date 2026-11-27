## Why

Services using client credentials need to keep authenticating while the issuer moves to Rust. The second direction of service-token revocation also depends on Rust issuing these credentials.

## What Changes

Support the client_credentials grant on the existing token endpoint. Compare issued credentials with the reference and verify that both services recognize revocation.

## Impact

The grant reads OAuth client registrations, updates their last-used timestamps and records issuance attempts.
