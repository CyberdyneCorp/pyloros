## ADDED Requirements

### Requirement: Decode identity layers in provider responses
The service SHALL decode token and profile documents containing one gzip or deflate coding alongside identity codings, whether combined in one Content-Encoding field or sent as repeated fields. Existing decoded document limits SHALL apply.

#### Scenario: Independent response headers
- **WHEN** a provider combines identity with gzip on its token response and sends identity and deflate as separate profile response fields
- **THEN** the exchange reads both documents and returns the provider subject
