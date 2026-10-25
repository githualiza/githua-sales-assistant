-- Internal delivery approval only. No email sending.
CREATE TABLE IF NOT EXISTS business_document_delivery_reviews (
 preparation_id TEXT PRIMARY KEY REFERENCES business_document_delivery_preparations(id),
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 status TEXT NOT NULL CHECK(status IN ('ready_for_review','approved')),
 snapshot_recipient TEXT NOT NULL,
 snapshot_subject TEXT NOT NULL,
 snapshot_message TEXT NOT NULL,
 requested_by TEXT NOT NULL REFERENCES users(id),
 requested_at TEXT NOT NULL,
 approved_by TEXT REFERENCES users(id),
 approved_at TEXT
);
CREATE TABLE IF NOT EXISTS business_document_delivery_review_events (
 id TEXT PRIMARY KEY,
 preparation_id TEXT NOT NULL REFERENCES business_document_delivery_preparations(id),
 organization_id TEXT NOT NULL REFERENCES organizations(id),
 actor_user_id TEXT NOT NULL REFERENCES users(id),
 action TEXT NOT NULL CHECK(action IN ('submit','approve')),
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delivery_review_events ON business_document_delivery_review_events(organization_id,preparation_id,created_at DESC);
