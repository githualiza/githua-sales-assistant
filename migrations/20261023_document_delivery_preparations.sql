-- Delivery preparation only: no external messages are sent by this release.
CREATE TABLE IF NOT EXISTS business_document_delivery_preparations (
 id TEXT PRIMARY KEY,
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 document_id TEXT NOT NULL REFERENCES business_documents(id),
 prepared_by TEXT NOT NULL REFERENCES users(id),
 recipient_email TEXT NOT NULL,
 subject TEXT NOT NULL,
 message TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'prepared' CHECK(status='prepared'),
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_document_delivery_preparations ON business_document_delivery_preparations(organization_id,document_id,created_at DESC);
