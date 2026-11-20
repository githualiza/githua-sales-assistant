# C1.1 — Offline schema review and authorization boundary

This is a **proposal, not an applied migration**. The file `docs/c1-1-proposed-staging-schema.sql` deliberately lives outside the Cloudflare `migrations/` directory: merging this branch must not cause automatic schema changes when the manual staging deploy workflow runs.

## Intent

Add separate organization-scoped customer, invoice, payment, receipt, sequence, and financial audit records. Existing `business_documents` invoice drafts, approvals and delivery preparations are not modified or copied. The future implementation must explicitly decide whether to adapt legacy invoice drafts or link them as sources without duplication.

## Critical acceptance gates before any SQL moves to migrations/

1. Run proposed SQL on a **disposable local D1/SQLite database** with a complete copy of prerequisite migration *schemas* and foreign keys enabled; never access staging or production for this step.
2. Test all cross-tenant foreign keys, unique references, duplicate provider references, duplicate receipts, malformed amounts, null references, and attempted deletion of related records. Verify with `PRAGMA foreign_key_check`.
3. Review SQLite FK behavior for nullable composite keys, and ensure service code checks source legacy document organization IDs (the legacy `business_documents` table does not expose a composite organization+id unique index).
4. A receipt must be created only for an invoice-linked verified payment, with matching tenant, currency, amount, and matching invoice ID; constraints alone do **not** enforce all of this. Use an audited, atomic authorization boundary and a suitable uniqueness strategy.
5. A payment cannot be marked verified solely from client claims or AI interpretations; authorization, immutable verification evidence, reversals and audited status transitions need additional specification. Prevent a net amount exceeding the issued invoice, including concurrent partial payments. Do not trust client-supplied totals.
6. Issued invoice snapshots cannot be silently modified: implement update guards, revision/credit-note rules, and transaction-safe per-tenant invoice/receipt number issuance.
7. Verify permitted currencies and their minor-unit precision; C1.0 tax-exclusive math is not sufficient for tax-inclusive/exempt fiscal use.
8. Define delivery consent and opt-in automation policies separately; no dispatch tables, queues or provider tokens are included.

## Permissions proposal

- Viewer: read only within an active organization when authorized by policy.
- Agent: prepare draft invoices and record proposed payments only, not verify, issue receipts or send messages.
- Manager: review/issue invoices and manually verify payments within policies, with actor audit.
- Owner/admin: configure organization business profile, approve payment corrections, decide per-channel sending policies.
- Any external send: separately gated by recipient verification, explicit authorization, dispatch idempotency, log, provider confirmation, revocation and kill switch.

## Deployment boundaries

- No code routes, existing Worker config, secrets, or migrations are changed in C1.1 offline draft.
- Before real staging migration, create a separate draft PR, perform offline disposable D1 validation, obtain explicit staging authorization, and use a targeted staging deployment. Nothing auto-applies to production.
- PR #89 Daily Focus remains separate and is not in scope.
