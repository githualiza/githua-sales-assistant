-- Tenant-scoped business document drafts. Apply before deploying API changes.
CREATE TABLE IF NOT EXISTS business_documents (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  created_by TEXT NOT NULL REFERENCES users(id),
  updated_by TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK (kind IN ('invoice','quotation','proposal','budget')),
  reference TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','ready_for_review')),
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(organization_id, kind, reference)
);
CREATE INDEX IF NOT EXISTS idx_business_documents_tenant_updated ON business_documents(organization_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS business_document_sequences (
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  kind TEXT NOT NULL CHECK (kind IN ('invoice','quotation','proposal','budget')),
  last_number INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (organization_id, kind)
);
