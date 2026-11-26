# Pyloros

Pyloros is a planned identity and authorization service with a Rust backend. Applications will use it to sign people in and decide what they can do. The project is in the specification phase.

## Authorization

Role-based access control (RBAC) will let an application assign permissions to roles. For example, a reviewer might be allowed to approve submissions for one organization.

Relationship-based access control (ReBAC) will let an application grant access through relationships between people and resources. A reviewer might be allowed to open a particular submission because it belongs to a collection shared with their team. Applications can require both the reviewer role and access to that submission.

## Compatibility goals

The design starts from the experience of application developers, users and operators. Priorities include interoperable sign-in and token handling, account and session management, administrative tools, auditability, and reliable integration events. Compatibility will be assessed through observable behavior and migration tests as the service develops.

## Extension hooks

The hook language is an open design decision. One option is to run WebAssembly extensions with explicit permissions and resource limits. The project will evaluate authoring tools, isolation, diagnostics and a migration path for existing scripts before selecting a runtime.
