-- Unique attempt identifier ensures audit events correspond to a successful approval transition.
ALTER TABLE business_document_delivery_approvals ADD COLUMN transition_id TEXT;
