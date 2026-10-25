# PR #68 — Secure Document Delivery Approval Contract

Status: implementation specification; NOT production-ready. Email sending remains disabled.

## Access control
- Only active tenant Owner or Admin may approve, reject, or revoke a prepared delivery.
- Managers, agents, viewers and unauthenticated users cannot approve; enforce on the server, not just UI.
- Read and mutation queries must scope by authenticated tenant and document ID; cross-tenant identifiers return 404.
- Never accept role, tenant, approver, or approval timestamp from the client.

## State machine
- prepared -> pending_approval -> approved | rejected
- rejected -> prepared only after explicit revision
- approved -> pending_approval when recipient, subject, body, attachment/document version, or approval-relevant metadata changes.
- revoked approval cannot be reused.
- Approval does NOT mean sent. All delivery records must display NOT SENT.
- Concurrent approval or edit requests use atomic conditional updates and reject stale versions.

## Audit requirements
- Append-only events: preparation_created, preparation_updated, approval_requested, approved, rejected, approval_revoked, unauthorized_attempt.
- Include event ID, tenant ID, preparation ID, document ID, authenticated actor ID/role, server timestamp, action, prior/new state, document version/hash, and optional reason.
- Avoid storing email bodies, tokens or sensitive attachment contents in logs.
- Never allow clients to edit or delete audit events.
- Provide tenant-scoped, Owner/Admin-only audit history with pagination and deterministic ordering.
- Rejected and unauthorized operations should not disclose other tenants' existence.

## Delivery safety
- No email provider integration, SMTP, send endpoint, outbound queue, webhook, or automatic dispatch.
- Explicit feature flag DOCUMENT_DELIVERY_SENDING_ENABLED=false; code must fail closed if unset.
- All actions terminate at internal approval, not delivery.
- No downloadable external public link or unscoped attachment access.
- UI clearly says "Approved internally — Not sent".

## Release acceptance tests
1. Owner and Admin can approve/reject only within their tenant.
2. Manager/Agent/Viewer cannot approve, even via direct HTTP requests.
3. Anonymous and cross-tenant requests cannot read or mutate.
4. Every successful transition emits exactly one immutable audit event.
5. Stale approval fails after document or recipient changes.
6. Parallel approve/edit cannot produce an approval of stale content.
7. Rejection reason is preserved without exposing sensitive content.
8. No outgoing emails, queued messages or provider API calls in tests.
9. Existing prepared-email create/edit and document review workflows still work.
10. Migration applies before Worker deployment; rollback and backup procedure reviewed.

## Rollout gate
This file is a requirements contract only. Implement backend, D1 migration, UI and automated tests before marking PR ready or merging. Keep production sending disabled throughout.
