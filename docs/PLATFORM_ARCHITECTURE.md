# Githua Sales Assistant Platform Architecture

## Product boundary

The platform is designed as a multi-user, multi-tenant SaaS product from the start.

- **Platform**: Githua AI Systems controls the service.
- **Organization**: each subscribing company has an isolated workspace.
- **User**: a human account may belong to one or more organizations.
- **Membership**: joins a user to an organization and assigns a role.
- **Lily**: public customer-facing assistant. It uses a separate public security path and must never inherit employee privileges.
- **Sales Assistant**: authenticated internal application for owners and employees.

## Roles

Initial roles are:

- `owner`: organization ownership, billing, security, members and all workspace data.
- `admin`: members, configuration, knowledge, leads and conversations; no ownership transfer.
- `manager`: sales team operations, leads, conversations and reporting.
- `agent`: assigned sales work, conversations and permitted lead updates.
- `viewer`: read-only access to permitted workspace information.

Authorization is enforced by the backend. The browser UI is not a security boundary.

## Tenant isolation

Every tenant-owned database row carries an `organization_id`. Backend handlers derive the active organization from the authenticated user's membership and never trust a browser-supplied organization ID by itself.

Cross-tenant access is denied by default. Platform-owner capabilities must use a separate, audited administrative path rather than bypassing tenant checks inside ordinary endpoints.

## Authentication

The commercial application will use standards-based authentication (OIDC/OAuth 2.0) with server-side verification of signed tokens. Provider-specific logic belongs behind an authentication adapter so the platform is not permanently tied to one identity vendor.

Before employee login endpoints are enabled in production, configure a production identity provider with:

- MFA support
- verified email addresses
- invitation flows
- account recovery
- short-lived access tokens
- signing-key rotation/JWKS
- session revocation

No password database will be implemented inside this Worker.

## Data domains

The first persistent domains are:

- organizations
- users (external identity references only)
- memberships
- leads
- conversations
- messages
- knowledge sources/documents
- audit events
- usage events
- integration connections (references to encrypted credentials, never raw secrets in application tables)
- subscription/billing metadata

## AI execution

AI requests are authorized before model invocation. The server owns system instructions and model policy. Public users cannot submit system-role messages on Lily's public route.

Each model request should be attributable to an organization, user/session and usage event for cost controls without deliberately logging full prompts or model responses.

## Commercialization

Commercial tenants receive isolated organizations, their own members, knowledge and sales data. Branding, model policy, quotas, integrations and billing are tenant configuration.

Githua AI Systems is the first organization and dogfoods the same tenant architecture used by future customers.

## Delivery phases

1. Public Lily security path (Turnstile, short-lived sessions, origin controls, rate limiting).
2. Identity provider + authenticated employee sessions.
3. D1 tenant schema + organization/membership authorization.
4. Sales dashboard + leads, conversations and knowledge.
5. Permissioned integrations and auditable actions.
6. Usage metering, quotas and billing.
7. Commercial tenant onboarding, branding and self-service administration.

Production changes continue through reviewed pull requests and the protected production deployment environment.
