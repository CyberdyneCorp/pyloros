## ADDED Requirements

### Requirement: Render the provisioning URI as an enrollment image
The service SHALL return a percent-encoded UTF-8 SVG data URI containing a QR symbol for the exact provisioning URI. Render each module at five intrinsic pixels and include a four-module quiet zone around the symbol.

#### Scenario: Display an authenticator enrollment image
- **WHEN** the first-party console displays a newly generated QR image
- **THEN** a scan recovers the same provisioning URI returned alongside the image
