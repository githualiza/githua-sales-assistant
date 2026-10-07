ALTER TABLE knowledge_sources ADD COLUMN category TEXT NOT NULL DEFAULT 'general';
ALTER TABLE knowledge_sources ADD COLUMN content TEXT;
ALTER TABLE knowledge_sources ADD COLUMN created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_knowledge_org_category ON knowledge_sources(organization_id, category, status);
