## ADDED Requirements

### Requirement: Replace role permissions
The service SHALL allow an administrator to replace the permissions of an existing global role with a set of registered keys belonging to that client and audit the resulting set.

#### Scenario: Clear the grants
- **WHEN** the administrator submits an empty list
- **THEN** all grants for that role are removed and the audit entry records an empty list

#### Scenario: Replacement cannot commit
- **WHEN** a permission is unknown or audit persistence fails
- **THEN** the stored mapping remains intact

#### Scenario: Two Pyloros writers replace one role
- **WHEN** both replacements complete successfully
- **THEN** the stored set equals the last committed replacement
