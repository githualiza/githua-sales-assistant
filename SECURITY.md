# Security

Never commit API keys, tokens, customer credentials, or production secrets.

Required runtime secrets are configured outside source control:
- OPENAI_API_KEY
- OPENROUTER_API_KEY
- GATEWAY_API_KEY

GitHub Actions uses CLOUDFLARE_API_TOKEN as an encrypted repository secret.
CLOUDFLARE_ACCOUNT_ID should be stored as a GitHub Actions repository variable.

Production deployment is manual and uses the GitHub `production` environment so repository owners can add deployment protection/approval rules.
