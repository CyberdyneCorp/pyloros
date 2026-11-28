## MODIFIED Requirements

### Requirement: Select subscription metadata and expiry
For subscription grants, the service SHALL use the product and optional plan from the first item's price metadata when that metadata identifies a product. Otherwise it SHALL use subscription metadata. For period-end selection, the service SHALL interpret the historical Boolean values false and true as the integers zero and one respectively. The service SHALL prefer the subscription's integer period end, then the first item's integer period end, and otherwise store a null expiry.

#### Scenario: Subscription and item supply different dates
- **WHEN** both dates are integers and the first item's price metadata identifies a product
- **THEN** use the subscription date and the item's product and optional plan

#### Scenario: Item supplies the only integer date
- **WHEN** the subscription date is absent or nonintegral and the first item supplies an integer date
- **THEN** use the first item's date, including when the product comes from subscription metadata

#### Scenario: A later item supplies a date
- **WHEN** neither the subscription nor the first item supplies an integer date
- **THEN** leave the expiry null even if a subsequent item supplies a date

#### Scenario: A subscription carries a historical Boolean
- **WHEN** the subscription period end is false and the first item carries a later timestamp
- **THEN** the entitlement expires at the Unix epoch

#### Scenario: The first item supplies the expiry
- **WHEN** the subscription has no period end and the first item's period end is true
- **THEN** the entitlement expires one second after the Unix epoch
