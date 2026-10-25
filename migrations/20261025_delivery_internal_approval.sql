-- Internal delivery approval only. No outbound email capability.
CREATE TABLE IF NOT EXISTS business_document_delivery_approvals (
  preparation_id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  document_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending_approval','approved','rejected')),
  revision INTEGER NOT NULL DEFAULT 1,
  approved_fingerprint TEXT,
  actor_id TEXT,
  decision_reason TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delivery_approvals_tenant ON business_document_delivery_approvals(organization_id,updated_at);
CREATE TABLE IF NOT EXISTS business_document_delivery_audit (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  preparation_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  action TEXT NOT NULL,
  previous_status TEXT,
  new_status TEXT,
  revision INTEGER NOT NULL,
  reason TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delivery_audit_tenant ON business_document_delivery_audit(organization_id,preparation_id,created_at,id);
