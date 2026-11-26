## ADDED Requirements

### Requirement: Confirm sign-in by email
The configured mail provider SHALL deliver the match code, source address, device and browser confirmation URL to the account email address. The URL SHALL carry the one-time token in its fragment. SMTP submission SHALL verify the relay certificate and require encryption. The mock provider SHALL retain messages in a process-local outbox.

#### Scenario: SMTP unavailable
- **WHEN** the configured relay cannot securely accept the message
- **THEN** delivery returns a failure to the confirmation workflow

#### Scenario: Account base fallback
- **WHEN** no explicit account-links base is set
- **THEN** the email uses the origin of the configured OIDC login URL or post-login URL
