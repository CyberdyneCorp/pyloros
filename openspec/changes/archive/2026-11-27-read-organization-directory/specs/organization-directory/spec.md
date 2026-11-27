## ADDED Requirements

### Requirement: Read an organization member directory
Pyloros SHALL expose GET /api/v1/orgs/{org_id}/members to administrators and active service clients presenting a bearer token with directory:read. It SHALL return 404 for an unknown or inactive organization.

#### Scenario: User has two sources of membership
- **WHEN** the primary organization and an explicit membership both match the requested organization
- **THEN** the user appears once with ID, email, avatar URL and activity status

#### Scenario: Client requests a filtered page
- **WHEN** an authorized caller filters by email substring or activity
- **THEN** the response includes matching members and the filtered total, page and page size, with a default of 50 and maximum of 200 per page

#### Scenario: Service registration is disabled
- **WHEN** a disabled client presents its previously issued directory token
- **THEN** the directory returns HTTP 401
