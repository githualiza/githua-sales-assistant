# Security

Never commit API keys, tokens, customer credentials, or production secrets.

Current Cloudflare Worker runtime secrets:
- OPENROUTER_API_KEY
- GATEWAY_API_KEY

The architecture keeps a provider abstraction so a direct OpenAI API connection can be added later without exposing provider credentials to clients.

GitHub Actions uses CLOUDFLARE_API_TOKEN as an encrypted repository secret.
CLOUDFLARE_ACCOUNT_ID is stored as a GitHub Actions repository variable.

Production deployment is manual and uses the GitHub `production` environment so repository owners can add deployment protection/approval rules.

Application code must not deliberately log API keys, customer prompts, or complete model responses.
