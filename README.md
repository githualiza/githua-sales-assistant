# Githua Sales Assistant

Secure AI sales-assistant backend for Githua AI Systems.

Architecture: GitHub → GitHub Actions → Cloudflare Worker → Githua AI Gateway → OpenAI (primary) + OpenRouter (specialist/fallback).

Production deployments are approval-gated. Secrets must never be committed to this repository.
