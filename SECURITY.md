# Security

Never commit API keys, tokens, customer credentials, identity-provider secrets, Turnstile secrets, signing secrets, or production credentials.

## Runtime secrets

Current private AI gateway:
- `OPENROUTER_API_KEY`
- `GATEWAY_API_KEY`

Planned public Lily path:
- `PUBLIC_SESSION_SECRET`
- `TURNSTILE_SECRET_KEY`

Future authenticated Sales Assistant:
- identity-provider secrets, if the selected OIDC provider requires them, remain encrypted runtime secrets
- application code verifies identity-provider signatures and tenant membership before accessing tenant data or invoking privileged actions

## Tenant isolation

All tenant-owned data must carry `organization_id`. Backend authorization derives tenant access from authenticated membership. Never authorize access solely because a browser supplied an organization ID, lead ID, conversation ID, or other object ID.

Platform administration must use a distinct, audited path.

## Secret handling

Provider abstraction allows AI providers to change without exposing credentials to clients.

GitHub Actions uses `CLOUDFLARE_API_TOKEN` as an encrypted repository secret. `CLOUDFLARE_ACCOUNT_ID` is a GitHub Actions repository variable.

Production deployment is manual and uses the GitHub `production` environment with deployment protection.

Application code must not deliberately log API keys, authentication tokens, customer prompts, complete model responses, or raw integration credentials.

## Browser boundary

The browser is untrusted. `GATEWAY_API_KEY`, `OPENROUTER_API_KEY` and integration credentials must never be embedded in frontend JavaScript.

Lily public access and employee Sales Assistant access are separate security paths. Public Lily sessions never grant employee or tenant-management permissions.
