-- Expand document status choices while preserving existing document IDs, references and payloads.
-- D1 applies migrations transactionally.
CREATE TABLE business_documents_new (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  created_by TEXT NOT NULL REFERENCES users(id),
  updated_by TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK (kind IN ('invoice','quotation','proposal','budget')),
  reference TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','ready_for_review','approved','rejected')),
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(organization_id,kind,reference)
);
INSERT INTO business_documents_new(id,organization_id,created_by,updated_by,kind,reference,status,payload_json,created_at,updated_at)
SELECT id,organization_id,created_by,updated_by,kind,reference,status,payload_json,created_at,updated_at FROM business_documents;
DROP TABLE business_documents;
ALTER TABLE business_documents_new RENAME TO business_documents;
CREATE INDEX IF NOT EXISTS idx_business_documents_tenant_updated ON business_documents(organization_id,updated_at DESC);
CREATE TABLE IF NOT EXISTS business_document_review_events (
 id TEXT PRIMARY KEY,
 document_id TEXT NOT NULL REFERENCES business_documents(id),
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 actor_user_id TEXT NOT NULL REFERENCES users(id),
 action TEXT NOT NULL CHECK (action IN ('submit','approve','reject','revise')),
 note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_document_review_events_doc ON business_document_review_events(organization_id,document_id,created_at DESC);
