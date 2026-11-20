# Phase C1 — Smart Invoicing, Receipts and Controlled Delivery

Status: **Design and offline domain foundation only**. This branch has no routes, schema migrations, credentials, workers, third-party connectors or sending enabled. **PR #89 (Daily Focus visibility) remains a separate stream.**

## Customer journey

1. Choose Create invoice or ask the assistant to prepare a draft; guided form must remain available if AI is unavailable.
2. Enter business and customer details, items, quantities, unit amounts, discounts, currency, due date, and explicitly configured tax treatment. Show preview and checklist before approving any data.
3. Save draft, submit for review, and approve/issue with role checks; lock issued snapshot, allocate a tenant-scoped invoice reference, and use documented revisions rather than silently editing an issued invoice.
4. Display unpaid, partially paid, paid or overdue using actual verified payment entries and due dates. Never equate a payment claim or screenshot with settlement.
5. Record payment amount, currency, reference, source, timestamp, verification actor and audit. Implement unique provider event reference and signed webhook validation in a later stage before provider reconciliation.
6. Prepare a receipt from a *verified* payment, including partial payments, with a one-receipt-per-payment guarantee and explicit reversal handling. A generic PDF is not proof of fiscal/tax compliance.
7. Provide branded, accessible PDF preview/download with escaped text, issuer, customer, invoice reference, currency, totals, payment details, time and history.
8. Offer (A) manual downloaded document sharing and (B) provider-backed email and WhatsApp messaging only when separately approved. Optional automation must be opt-in per workspace and channel, with preview, audit, idempotency and emergency kill switch.

## Safety and integration policy

- Keep DOCUMENT_DELIVERY_SENDING_ENABLED=false. C1.0 adds no send route, live connector, new queue, or outbound messages.
- Sending to email requires verified sending domain, consent where applicable, recipient confirmation, rate limits, bounce handling, delivery event logging and duplicate-send protection.
- WhatsApp Business requires an official supported provider, compliant opt-ins, approved templates and conversation-window checks where applicable. A share link or file download is not equivalent to sending through the WhatsApp Business API.
- Automation remains OFF by default. It must be enabled with explicit owner authorization after confirming trigger, channel, template, scope, recipient validation and rollback controls.
- Protect customer and payment metadata with tenant isolation, least-privilege roles, retention limits and audit. Never store full payment-card credentials.

## Implementation gates

| Stage | Deliverable | Gate |
| --- | --- | --- |
| C1.0 (current) | Pure invoice arithmetic, payment reconciliation, receipt eligibility, explicitly disabled delivery defaults and tests | No routes, migrations, dispatch or changes to production |
| C1.1 | Staging-only invoice/customer snapshots, references, payments and receipt schema plus tenant-scoped CRUD and audit | Separate authorized staging migration and access-control tests |
| C1.2 | Guided invoice form, AI draft helper with manual fallback, branded PDF rendering, accessible previews | Accurate calculations and browser/PDF validation |
| C1.3 | Issue/review, immutable approved invoice versions, sequential IDs and corrections | Duplicate/unauthorized/modified record tests |
| C1.4 | Payment verification, partial payments, receipt PDF, reversal/duplicate handling | No receipt without verified payment |
| C1.5 | Manual PDF download and internal email/WhatsApp preparation only | No external message sent |
| C1.6 | Approved email and WhatsApp provider integrations, still disabled behind feature flags | Sandbox send, failure, consent, dedupe and audit tests |
| C1.7 | Optional per-workspace delivery automation and revocation | Owner opt-in, safety limits, kill switch, security testing |
| C1.8 | Separate production readiness and explicit go-live approval | Compliance and rollback review, production permission |

## Tax and calculations

- Do not assume a default VAT or sales tax rate. Organization configuration or explicit user entry must determine tax applicability, including any exemptions and inclusive vs exclusive tax handling. Current C1.0 functions implement **tax-exclusive** integer-minor-unit calculations only.
- Kenyan invoices and receipts may need KRA eTIMS requirements; a PDF alone must not be represented as an approved fiscal invoice. Confirm current KRA rules before implementation.
- Multi-currency processing must respect each currency's minor-unit precision and explicit rounding rules; never float currency values or silently convert.
- A recorded verified payment means an authorized person or authenticated provider confirmed it; the current pure module does not itself verify settlement.

## Non-regression

- Preserve original champagne/lavender dashboard, Show me how, document approvals, and existing read-only next-actions experience.
- Keep all current application routes and database schema unchanged in C1.0. Merging PR #89 is not part of this work.
- CI and staging UAT are required between stages. Never deploy or merge automatically.
